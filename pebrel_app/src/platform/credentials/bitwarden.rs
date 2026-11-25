//! Bitwarden CLI adapters. The CLI owns vault authentication and server selection.

use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pebrel_settings::{CredentialBackend, CredentialStoreSettings};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

use crate::platform::process::{ProcessGroup, configure_process_group};

const TIMEOUT: Duration = Duration::from_secs(15);
const OUTPUT_LIMIT: u64 = 32 * 1024 * 1024;
type Bytes = Zeroizing<Vec<u8>>;

pub(super) fn find_cli(name: &str, configured: &str) -> Option<PathBuf> {
    let find = |path: &Path| {
        #[cfg(windows)]
        if path.extension().is_none() {
            // The official standalone binary and the npm launcher use these extensions.
            for extension in ["exe", "cmd"] {
                let candidate = path.with_extension(extension);
                if candidate.is_file() {
                    return std::path::absolute(candidate).ok();
                }
            }
        }
        let metadata = path.metadata().ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                return None;
            }
        }
        metadata.is_file().then(|| std::path::absolute(path).ok()).flatten()
    };
    if !configured.is_empty() {
        return find(Path::new(configured));
    }
    std::env::var_os("PATH")
        .as_deref()
        .and_then(|paths| std::env::split_paths(paths).find_map(|dir| find(&dir.join(name))))
}

pub(super) trait Runner {
    fn run(&self, args: &[&str], input: Option<Bytes>) -> io::Result<CliOutput>;
}

pub(super) struct CommandRunner<'a>(pub(super) &'a Path);

pub(super) struct CliOutput {
    success: bool,
    stdout: Bytes,
    stderr: Bytes,
}

impl Runner for CommandRunner<'_> {
    fn run(&self, args: &[&str], input: Option<Bytes>) -> io::Result<CliOutput> {
        let mut command = Command::new(self.0);
        command.args(args);
        run_command(command, input, TIMEOUT).map_err(|error| {
            let message = match error.kind() {
                io::ErrorKind::NotFound => {
                    "Bitwarden CLI was not found. Check its path and restart Pebrel"
                },
                io::ErrorKind::PermissionDenied => {
                    "Bitwarden CLI could not be executed. Check its permissions"
                },
                io::ErrorKind::TimedOut => {
                    "Bitwarden CLI timed out. Check vault connectivity and unlock state"
                },
                _ => "Bitwarden CLI input or output failed",
            };
            io::Error::new(error.kind(), message)
        })
    }
}

fn run_command(
    mut command: Command,
    input: Option<Bytes>,
    timeout: Duration,
) -> io::Result<CliOutput> {
    command
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let mut child = command.spawn()?;
    let group = match ProcessGroup::attach(&child) {
        Ok(group) => group,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        },
    };
    let result = exchange(&mut child, input, Instant::now() + timeout);
    if result.is_err() {
        group.terminate(&mut child);
        let _ = child.wait();
    }
    result
}

fn exchange(child: &mut Child, input: Option<Bytes>, deadline: Instant) -> io::Result<CliOutput> {
    fn drain(
        reader: impl std::io::Read + Send + 'static,
    ) -> io::Result<thread::JoinHandle<io::Result<Bytes>>> {
        thread::Builder::new().spawn(move || {
            let mut bytes = Bytes::default();
            reader.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > OUTPUT_LIMIT {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(bytes)
        })
    }

    let stdout = drain(child.stdout.take().unwrap())?;
    let stderr = drain(child.stderr.take().unwrap())?;
    let writer = if let Some(input) = input {
        let mut stdin = child.stdin.take().unwrap();
        Some(thread::Builder::new().spawn(move || stdin.write_all(&input))?)
    } else {
        None
    };

    let success = loop {
        if let Some(status) = child.try_wait()?
            && stdout.is_finished()
            && stderr.is_finished()
            && writer.as_ref().is_none_or(thread::JoinHandle::is_finished)
        {
            break status.success();
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(Duration::from_millis(10));
    };

    if let Some(writer) = writer {
        let written = writer.join().map_err(|_| io::Error::other("CLI input worker failed"))?;
        if success {
            written?;
        }
    }
    Ok(CliOutput {
        success,
        stdout: stdout.join().map_err(|_| io::Error::other("CLI output worker failed"))??,
        stderr: stderr.join().map_err(|_| io::Error::other("CLI error worker failed"))??,
    })
}

pub(super) struct Bitwarden<'a, R> {
    settings: &'a CredentialStoreSettings,
    runner: R,
}

impl<'a, R: Runner> Bitwarden<'a, R> {
    pub(super) fn new(settings: &'a CredentialStoreSettings, runner: R) -> Self {
        Self { settings, runner }
    }

    pub(super) fn load(&self, target: &str) -> io::Result<Option<Vec<u8>>> {
        validate_argument(target)?;
        match self.settings.backend {
            CredentialBackend::BitwardenBw => {
                let Some(item) = self.bw_find(target)? else { return Ok(None) };
                Ok(item.0["login"]["password"].as_str().map(|secret| secret.as_bytes().to_vec()))
            },
            CredentialBackend::BitwardenRbw => {
                let Some(id) = self.rbw_find(target)? else { return Ok(None) };
                let Some(mut secret) = self.rbw_call(&["get", &id], None)? else { return Ok(None) };
                std::str::from_utf8(&secret).map_err(|_| invalid_output())?;
                if secret.last() == Some(&b'\n') {
                    secret.pop();
                    Ok(Some(std::mem::take(&mut *secret)))
                } else if secret.is_empty() {
                    // rbw emits no stdout for a login without a password.
                    Ok(None)
                } else {
                    Err(invalid_output())
                }
            },
            CredentialBackend::System => unreachable!("system credentials do not use a CLI"),
        }
    }

    pub(super) fn store(&self, target: &str, username: &str, secret: &[u8]) -> io::Result<()> {
        validate_argument(target)?;
        validate_argument(username)?;
        let secret = std::str::from_utf8(secret).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Bitwarden passwords must be valid UTF-8")
        })?;
        if secret.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Bitwarden passwords cannot contain NUL",
            ));
        }

        match self.settings.backend {
            CredentialBackend::BitwardenBw => self.bw_store(target, username, secret),
            CredentialBackend::BitwardenRbw => self.rbw_store(target, username, secret),
            CredentialBackend::System => unreachable!("system credentials do not use a CLI"),
        }
    }

    pub(super) fn delete(&self, target: &str) -> io::Result<()> {
        validate_argument(target)?;
        match self.settings.backend {
            CredentialBackend::BitwardenBw => {
                if let Some(item) = self.bw_find(target)? {
                    let id = item_id(&item.0)?;
                    self.bw_call(&["delete", "item", id], None)?;
                }
            },
            CredentialBackend::BitwardenRbw => {
                if let Some(id) = self.rbw_find(target)? {
                    self.rbw_call(&["remove", &id], None)?;
                }
            },
            CredentialBackend::System => unreachable!("system credentials do not use a CLI"),
        }
        Ok(())
    }

    fn bw_call(&self, args: &[&str], input: Option<Bytes>) -> io::Result<Bytes> {
        let output = self.runner.run(args, input)?;
        if output.success { Ok(output.stdout) } else { Err(cli_failure("bw", &output.stderr)) }
    }

    fn bw_folder(&self, folder: &str, create: bool) -> io::Result<Option<String>> {
        let output = self.bw_call(&["list", "folders", "--search", folder], None)?;
        let folders = parse_json(&output)?;
        let found =
            find_unique(folders.0.as_array().ok_or_else(invalid_output)?.iter(), |value| {
                value["name"].as_str() == Some(folder)
            })?;
        if let Some(found) = found {
            return Ok(Some(item_id(found)?.to_owned()));
        }
        if !create {
            return Ok(None);
        }
        let input = bw_payload(&json!({"name": folder}))?;
        let output = self.bw_call(&["create", "folder"], Some(input))?;
        Ok(Some(item_id(&parse_json(&output)?.0)?.to_owned()))
    }

    fn bw_find(&self, target: &str) -> io::Result<Option<SensitiveJson>> {
        let folder = &self.settings.bitwarden_folder;
        let folder_id = if folder.is_empty() {
            None
        } else {
            let Some(id) = self.bw_folder(folder, false)? else { return Ok(None) };
            Some(id)
        };
        self.bw_find_in(target, folder_id.as_deref())
    }

    fn bw_find_in(&self, target: &str, folder: Option<&str>) -> io::Result<Option<SensitiveJson>> {
        let mut args = vec!["list", "items", "--search", target];
        if let Some(folder) = folder {
            args.extend(["--folderid", folder]);
        }
        let output = self.bw_call(&args, None)?;
        let mut items = parse_json(&output)?;
        let items = items.0.as_array_mut().ok_or_else(invalid_output)?;
        let index = find_unique(0..items.len(), |&index| {
            let item = &items[index];
            item["name"].as_str() == Some(target)
                && folder.is_none_or(|id| item["folderId"].as_str() == Some(id))
        })?;
        Ok(index.map(|index| SensitiveJson(items.swap_remove(index))))
    }

    fn bw_store(&self, target: &str, username: &str, secret: &str) -> io::Result<()> {
        let folder = &self.settings.bitwarden_folder;
        let folder_id = if folder.is_empty() { None } else { self.bw_folder(folder, true)? };
        let existing = self.bw_find_in(target, folder_id.as_deref())?;
        let id = existing.as_ref().map(|item| item_id(&item.0).map(str::to_owned)).transpose()?;
        let mut item = existing.unwrap_or_else(|| SensitiveJson(json!({"name": target})));
        item.0["type"] = Value::from(1);
        if let Some(folder_id) = folder_id {
            item.0["folderId"] = Value::String(folder_id);
        }
        if item.0["login"].is_null() {
            item.0["login"] = json!({});
        }
        let login = item.0["login"].as_object_mut().ok_or_else(invalid_output)?;
        wipe_json(login.insert("username".to_owned(), Value::String(username.to_owned())).as_mut());
        wipe_json(login.insert("password".to_owned(), Value::String(secret.to_owned())).as_mut());
        let args = if let Some(id) = id.as_deref() {
            &["edit", "item", id][..]
        } else {
            &["create", "item"][..]
        };
        self.bw_call(args, Some(bw_payload(&item.0)?))?;
        Ok(())
    }

    fn rbw_find(&self, target: &str) -> io::Result<Option<String>> {
        let status = self.runner.run(&["unlocked"], None)?;
        if !status.success {
            if status.stderr.is_empty() {
                return Err(locked("rbw"));
            }
            return Err(cli_failure("rbw", &status.stderr));
        }
        // JSON avoids ambiguity when an unrelated vault entry contains a tab or newline.
        let output =
            self.runner.run(&["list", "--fields", "id,name,user,folder", "--raw"], None)?;
        if !output.success {
            return Err(cli_failure("rbw", &output.stderr));
        }
        let entries: Vec<RbwEntry> =
            serde_json::from_slice(&output.stdout).map_err(|_| invalid_output())?;
        let folder = &self.settings.bitwarden_folder;
        let found = find_unique(entries, |entry| {
            entry.name == target && entry.folder.as_deref().unwrap_or("") == folder
        })?;
        found.map(|entry| rbw_id(entry.id)).transpose()
    }

    fn rbw_call(&self, args: &[&str], input: Option<Bytes>) -> io::Result<Option<Bytes>> {
        let output = self.runner.run(args, input)?;
        if output.success {
            return Ok(Some(output.stdout));
        }
        let stderr = std::str::from_utf8(&output.stderr).map_err(|_| invalid_output())?;
        let stderr = stderr.trim();
        if stderr == "no entry found"
            || (stderr.starts_with("couldn't find entry for '")
                && stderr.ends_with("': no entry found"))
        {
            return Ok(None);
        }
        Err(cli_failure("rbw", &output.stderr))
    }

    fn rbw_store(&self, target: &str, username: &str, secret: &str) -> io::Result<()> {
        if secret.is_empty() || secret.contains(['\r', '\n']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rbw passwords must be non-empty and contain no line breaks",
            ));
        }
        let mut input = Bytes::new(Vec::with_capacity(secret.len() + 1));
        input.extend_from_slice(secret.as_bytes());
        input.push(b'\n');
        if let Some(id) = self.rbw_find(target)? {
            if self.rbw_call(&["edit", &id], Some(input))?.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "rbw entry was removed before it could be updated",
                ));
            }
        } else {
            let mut args = vec!["add"];
            let folder = &self.settings.bitwarden_folder;
            if !folder.is_empty() {
                args.extend(["--folder", folder]);
            }
            args.extend(["--", target]);
            if !username.is_empty() {
                args.push(username);
            }
            let output = self.runner.run(&args, Some(input))?;
            if !output.success {
                return Err(cli_failure("rbw", &output.stderr));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RbwEntry {
    id: String,
    name: String,
    folder: Option<String>,
}

fn find_unique<T>(
    entries: impl IntoIterator<Item = T>,
    matches: impl Fn(&T) -> bool,
) -> io::Result<Option<T>> {
    let mut matches = entries.into_iter().filter(matches);
    let found = matches.next();
    if matches.next().is_some() {
        return Err(io::Error::other(
            "Multiple matching Bitwarden entries. Rename or remove duplicates in the vault",
        ));
    }
    Ok(found)
}

fn rbw_id(id: String) -> io::Result<String> {
    // A malformed id would be interpreted as a name by rbw, invoking fuzzy matching.
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_hexdigit() }
        })
    {
        return Err(invalid_output());
    }
    Ok(id)
}

fn item_id(value: &Value) -> io::Result<&str> {
    value["id"]
        .as_str()
        .filter(|id| !id.is_empty() && !id.starts_with('-') && !id.chars().any(char::is_control))
        .ok_or_else(invalid_output)
}

fn validate_argument(value: &str) -> io::Result<()> {
    if value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Bitwarden credential names and usernames cannot contain control characters",
        ));
    }
    Ok(())
}

fn bw_payload(value: &Value) -> io::Result<Bytes> {
    let mut json = Bytes::default();
    serde_json::to_writer(&mut *json, value).map_err(|_| invalid_output())?;
    let mut encoded =
        Bytes::new(vec![0; base64::encoded_len(json.len(), true).ok_or_else(invalid_output)?]);
    STANDARD.encode_slice(&json, &mut encoded).map_err(|_| invalid_output())?;
    Ok(encoded)
}

fn parse_json(output: &[u8]) -> io::Result<SensitiveJson> {
    serde_json::from_slice(output).map(SensitiveJson).map_err(|_| invalid_output())
}

struct SensitiveJson(Value);

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        wipe_json(Some(&mut self.0));
    }
}

fn wipe_json(value: Option<&mut Value>) {
    match value {
        Some(Value::String(text)) => text.zeroize(),
        Some(Value::Array(items)) => items.iter_mut().for_each(|item| wipe_json(Some(item))),
        Some(Value::Object(fields)) => fields.values_mut().for_each(|item| wipe_json(Some(item))),
        _ => {},
    }
}

fn invalid_output() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Bitwarden CLI returned malformed data. Check the CLI version",
    )
}

fn locked(program: &str) -> io::Error {
    let hint = if program == "bw" {
        "Bitwarden vault is locked. Unlock with bw and make BW_SESSION available to Pebrel"
    } else {
        "Bitwarden vault is locked. Run rbw unlock before retrying"
    };
    io::Error::new(io::ErrorKind::PermissionDenied, hint)
}

fn cli_failure(program: &str, stderr: &[u8]) -> io::Error {
    if std::str::from_utf8(stderr).is_err() {
        return invalid_output();
    }
    let contains = |pattern: &[u8]| {
        stderr.windows(pattern.len()).any(|part| part.eq_ignore_ascii_case(pattern))
    };
    if [
        b"not logged in".as_slice(),
        b"you are not logged in",
        b"unauthenticated",
        b"failed to find email address",
        b"login required",
    ]
    .into_iter()
    .any(contains)
    {
        let hint = if program == "bw" {
            "Sign in with bw login before retrying"
        } else {
            "Configure and sign in with rbw login before retrying"
        };
        io::Error::new(io::ErrorKind::PermissionDenied, hint)
    } else if [
        b"vault is locked".as_slice(),
        b"vault locked",
        b"agent is not running",
        b"agent not running",
        b"not unlocked",
        b"agent is locked",
    ]
    .into_iter()
    .any(contains)
    {
        locked(program)
    } else {
        io::Error::other(
            "Bitwarden CLI operation failed. Check the CLI configuration and vault access",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    const TARGET: &str = "Pebrel/SSH/host";
    const LEGACY: &str = "Nebula/SSH/host";
    const SECRET: &str = "synthetic password with spaces 密码";
    const UUID: &str = "125980a2-a3f5-445e-a806-3d864f2f56eb";
    const OLD_UUID: &str = "a0e46c6b-0f36-48b1-b803-e63db059384d";
    const RBW_LIST: &[&str] = &["list", "--fields", "id,name,user,folder", "--raw"];
    const BW_LIST: &[&str] = &["list", "items", "--search", TARGET, "--folderid", "folder-id"];

    enum Input {
        None,
        Json(Value),
        Password,
    }

    struct Call<'a> {
        args: &'a [&'a str],
        input: Input,
        result: io::Result<CliOutput>,
    }

    fn ok<'a>(args: &'a [&'a str], stdout: impl AsRef<[u8]>) -> Call<'a> {
        Call {
            args,
            input: Input::None,
            result: Ok(CliOutput {
                success: true,
                stdout: Bytes::new(stdout.as_ref().to_vec()),
                stderr: Bytes::default(),
            }),
        }
    }

    fn failure<'a>(args: &'a [&'a str], stderr: &str) -> Call<'a> {
        let mut call = ok(args, []);
        let output = call.result.as_mut().unwrap();
        output.success = false;
        output.stderr.extend_from_slice(stderr.as_bytes());
        call
    }

    struct Script<'a>(RefCell<VecDeque<Call<'a>>>);

    impl<'a> Script<'a> {
        fn new(calls: impl IntoIterator<Item = Call<'a>>) -> Self {
            Self(RefCell::new(calls.into_iter().collect()))
        }
    }

    impl Runner for Script<'_> {
        fn run(&self, args: &[&str], input: Option<Bytes>) -> io::Result<CliOutput> {
            let call = self.0.borrow_mut().pop_front().expect("unexpected CLI call");
            assert!(args.iter().all(|arg| !arg.contains(SECRET)));
            assert_eq!(args, call.args);
            match call.input {
                Input::None => assert!(input.is_none()),
                Input::Password => {
                    assert_eq!(&**input.unwrap(), format!("{SECRET}\n").as_bytes());
                },
                Input::Json(expected) => {
                    let decoded = STANDARD.decode(&**input.unwrap()).unwrap();
                    assert_eq!(serde_json::from_slice::<Value>(&decoded).unwrap(), expected);
                },
            }
            call.result
        }
    }

    impl Drop for Script<'_> {
        fn drop(&mut self) {
            if !thread::panicking() {
                assert!(self.0.get_mut().is_empty(), "expected additional CLI calls");
            }
        }
    }

    fn bw_folder() -> Call<'static> {
        ok(
            &["list", "folders", "--search", "Pebrel"],
            r#"[{"name":"Pebrel old","id":"noise"},{"name":"Pebrel","id":"folder-id"}]"#,
        )
    }

    fn bw_item() -> Call<'static> {
        ok(
            BW_LIST,
            json!([
                {"name": "Pebrel/SSH/host extra", "login": {"password": "noise"}},
                {"name": TARGET, "folderId": "wrong-folder", "login": {"password": "noise"}},
                {"id": "item-id", "type": 1, "name": TARGET, "folderId": "folder-id",
                 "login": {"username": "old", "password": "old password", "uris": []}, "notes": "keep"}
            ])
            .to_string(),
        )
    }

    fn rbw_listing(entries: Value) -> [Call<'static>; 2] {
        [ok(&["unlocked"], []), ok(RBW_LIST, entries.to_string())]
    }

    fn rbw_item() -> Value {
        json!([
            {"id": OLD_UUID, "name": TARGET, "folder": "Pebrel copy"},
            {"id": OLD_UUID, "name": "Pebrel/SSH/host extra", "folder": "Pebrel"},
            {"id": UUID, "name": TARGET, "folder": "Pebrel", "user": "somebody"}
        ])
    }

    #[test]
    fn bw_loads_updates_and_removes_only_the_exact_item() {
        let settings = CredentialStoreSettings {
            backend: CredentialBackend::BitwardenBw,
            ..Default::default()
        };
        let mut edit = ok(&["edit", "item", "item-id"], []);
        edit.input = Input::Json(json!({
            "id":"item-id", "type":1, "name":TARGET, "folderId":"folder-id",
            "login":{"username":"new", "password":SECRET, "uris":[]}, "notes":"keep"
        }));
        let cli = Bitwarden::new(
            &settings,
            Script::new([
                bw_folder(),
                bw_item(),
                bw_folder(),
                bw_item(),
                edit,
                bw_folder(),
                bw_item(),
                ok(&["delete", "item", "item-id"], []),
                bw_folder(),
                ok(BW_LIST, "[]"),
            ]),
        );
        assert_eq!(cli.load(TARGET).unwrap().as_deref(), Some(b"old password".as_slice()));
        cli.store(TARGET, "new", SECRET.as_bytes()).unwrap();
        cli.delete(TARGET).unwrap();
        cli.delete(TARGET).unwrap();
    }

    #[test]
    fn bw_creates_a_missing_folder_only_for_store() {
        let settings = CredentialStoreSettings {
            backend: CredentialBackend::BitwardenBw,
            ..Default::default()
        };
        let missing = || ok(&["list", "folders", "--search", "Pebrel"], "[]");
        let mut folder = ok(&["create", "folder"], r#"{"id":"folder-id"}"#);
        folder.input = Input::Json(json!({"name":"Pebrel"}));
        let mut item = ok(&["create", "item"], []);
        item.input = Input::Json(json!({
            "type":1, "name":TARGET, "folderId":"folder-id",
            "login":{"username":"user", "password":SECRET}
        }));
        let cli = Bitwarden::new(
            &settings,
            Script::new([missing(), missing(), missing(), folder, ok(BW_LIST, "[]"), item]),
        );
        assert_eq!(cli.load(TARGET).unwrap(), None);
        cli.delete(TARGET).unwrap();
        cli.store(TARGET, "user", SECRET.as_bytes()).unwrap();
    }

    #[test]
    fn rbw_uses_ids_for_existing_items_and_folder_flags_only_to_add() {
        let settings = CredentialStoreSettings {
            backend: CredentialBackend::BitwardenRbw,
            ..Default::default()
        };
        let noise = json!([{"id": OLD_UUID, "name": "Pebrel/SSH/host extra", "folder": "Pebrel"}]);
        let mut add = ok(&["add", "--folder", "Pebrel", "--", TARGET, "user"], []);
        add.input = Input::Password;
        let mut edit = ok(&["edit", UUID], []);
        edit.input = Input::Password;
        let cli = Bitwarden::new(
            &settings,
            Script::new(
                rbw_listing(noise.clone())
                    .into_iter()
                    .chain([add])
                    .chain(rbw_listing(rbw_item()))
                    .chain([ok(&["get", UUID], format!("{SECRET}\n"))])
                    .chain(rbw_listing(rbw_item()))
                    .chain([edit])
                    .chain(rbw_listing(rbw_item()))
                    .chain([ok(&["remove", UUID], [])])
                    .chain(rbw_listing(noise)),
            ),
        );
        cli.store(TARGET, "user", SECRET.as_bytes()).unwrap();
        assert_eq!(cli.load(TARGET).unwrap().as_deref(), Some(SECRET.as_bytes()));
        cli.store(TARGET, "user", SECRET.as_bytes()).unwrap();
        cli.delete(TARGET).unwrap();
        cli.delete(TARGET).unwrap();
    }

    #[test]
    fn rbw_empty_folder_is_exact_and_duplicates_are_rejected() {
        let settings = CredentialStoreSettings {
            backend: CredentialBackend::BitwardenRbw,
            bitwarden_folder: String::new(),
            ..Default::default()
        };
        let cli = Bitwarden::new(
            &settings,
            Script::new(rbw_listing(json!([
                {"id": UUID, "name": TARGET, "folder": null},
                {"id": OLD_UUID, "name": TARGET, "folder": ""}
            ]))),
        );
        assert!(cli.delete(TARGET).unwrap_err().to_string().contains("Multiple"));
        let mut add = ok(&["add", "--", TARGET], []);
        add.input = Input::Password;
        let cli = Bitwarden::new(
            &settings,
            Script::new(rbw_listing(rbw_item()).into_iter().chain([add])),
        );
        cli.store(TARGET, "", SECRET.as_bytes()).unwrap();
    }

    #[test]
    fn invalid_passwords_are_rejected_before_any_cli_call() {
        for backend in [CredentialBackend::BitwardenBw, CredentialBackend::BitwardenRbw] {
            let settings = CredentialStoreSettings { backend, ..Default::default() };
            let cli = Bitwarden::new(&settings, Script::new([]));
            for secret in [b"bad\0value".as_slice(), &[0xff]] {
                assert_eq!(
                    cli.store(TARGET, "user", secret).unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                );
            }
            if backend == CredentialBackend::BitwardenRbw {
                for secret in ["", "first\nsecond", "first\rsecond"] {
                    assert_eq!(
                        cli.store(TARGET, "user", secret.as_bytes()).unwrap_err().kind(),
                        io::ErrorKind::InvalidInput,
                    );
                }
            }
        }
    }

    #[test]
    fn legacy_lookup_and_removal_use_the_application_identity_order() {
        let folderless = CredentialStoreSettings {
            backend: CredentialBackend::BitwardenBw,
            bitwarden_folder: String::new(),
            ..Default::default()
        };
        let legacy = || {
            ok(
                &["list", "items", "--search", LEGACY],
                json!([{"id":"legacy", "name":LEGACY, "login":{"password":SECRET}}]).to_string(),
            )
        };
        let current = || ok(&["list", "items", "--search", TARGET], "[]");
        let cli = Bitwarden::new(
            &folderless,
            Script::new([
                current(),
                legacy(),
                legacy(),
                ok(&["delete", "item", "legacy"], []),
                current(),
            ]),
        );
        exercise_legacy(&cli);

        let settings =
            CredentialStoreSettings { backend: CredentialBackend::BitwardenRbw, ..folderless };
        let listing = || rbw_listing(json!([{"id":OLD_UUID,"name":LEGACY,"folder":null}]));
        let cli = Bitwarden::new(
            &settings,
            Script::new(
                listing()
                    .into_iter()
                    .chain(listing())
                    .chain([ok(&["get", OLD_UUID], format!("{SECRET}\n"))])
                    .chain(listing())
                    .chain([ok(&["remove", OLD_UUID], [])])
                    .chain(listing()),
            ),
        );
        exercise_legacy(&cli);
    }

    fn exercise_legacy(cli: &Bitwarden<'_, Script<'_>>) {
        assert_eq!(
            super::super::load_with(LEGACY, |identity| cli.load(&identity.target))
                .unwrap()
                .as_deref(),
            Some(SECRET.as_bytes())
        );
        super::super::delete_with(LEGACY, |identity| cli.delete(&identity.target)).unwrap();
    }

    #[test]
    fn diagnostics_map_authentication_failures_without_echoing_cli_output() {
        let settings = CredentialStoreSettings {
            backend: CredentialBackend::BitwardenBw,
            bitwarden_folder: String::new(),
            ..Default::default()
        };
        let args = &["list", "items", "--search", TARGET];
        for (diagnostic, hint) in
            [("Vault is locked.", "Unlock with bw"), ("You are not logged in.", "bw login")]
        {
            let cli = Bitwarden::new(
                &settings,
                Script::new([failure(args, &format!("{diagnostic} {SECRET}"))]),
            );
            let error = cli.load(TARGET).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains(hint));
            assert!(!error.to_string().contains(SECRET));
        }

        let rbw = CredentialStoreSettings {
            backend: CredentialBackend::BitwardenRbw,
            ..settings.clone()
        };
        let cli = Bitwarden::new(&rbw, Script::new([failure(&["unlocked"], "agent not running")]));
        let error = cli.load(TARGET).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("rbw unlock"));

        let timeout =
            Call { args, input: Input::None, result: Err(io::ErrorKind::TimedOut.into()) };
        let cli = Bitwarden::new(&settings, Script::new([timeout]));
        assert_eq!(cli.load(TARGET).unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[cfg(unix)]
    #[test]
    fn real_runner_drains_both_pipes_during_stdin_and_times_out_a_blocked_writer() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2; cat"]);
        let output =
            run_command(command, Some(Bytes::new(vec![7; 131072])), Duration::from_secs(5))
                .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.len(), 262144);
        assert_eq!(output.stderr.len(), 131072);
        assert!(output.stdout[131072..].iter().all(|byte| *byte == 7));

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 20 & wait"]);
        let started = Instant::now();
        let error =
            run_command(command, Some(Bytes::new(vec![7; 262144])), Duration::from_millis(100))
                .err()
                .expect("expected timeout");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
