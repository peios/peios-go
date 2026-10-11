fn dump(b: &[u8]) {
    for v in b {
        print!("{v:02x}");
    }
    println!();
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn extra(mode: &str, arg: &str) -> bool {
    match mode {
        "native-sysv" => {
            use peios::file::{SecInfo, SysvKind};
            let (k, id) = arg.split_once('|').unwrap();
            let kind = match k {
                "0" => SysvKind::SharedMemory,
                "1" => SysvKind::MessageQueue,
                _ => SysvKind::SemaphoreArray,
            };
            match peios::file::sysv_get_sd(
                kind,
                id.parse().unwrap(),
                SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL,
            ) {
                Ok(sd) => dump(sd.as_bytes()),
                Err(_) => println!("error"),
            }
        }
        "native-mount" => {
            use std::os::fd::{FromRawFd, OwnedFd};
            let path = std::ffi::CString::new(arg).unwrap();
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            assert!(fd >= 0);
            let f = peios::file::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
            match f.mount_get_policy() {
                Ok(p) => {
                    print!("{} {} {} ", p.kind.0, p.flags, p.generation);
                    dump(p.template_sd.as_ref().map_or(&[], |s| s.as_bytes()));
                }
                Err(_) => println!("error"),
            }
        }
        "socket" => {
            use std::os::fd::{AsFd, FromRawFd, OwnedFd};
            let cap: usize = arg.parse().unwrap();
            let mut fds = [0; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                        0,
                        fds.as_mut_ptr(),
                    )
                },
                0
            );
            let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let f = std::fs::File::open("/dev/null").unwrap();
            let payload: &[u8] = if cap == 3 { b"" } else { b"hello" };
            let mut buffer = [0u8; 1];
            let sent =
                peios::socket::send_message(a.as_fd(), payload, None, &[f.as_fd(), f.as_fd()], 0)
                    .unwrap();
            let msg = peios::socket::recv_message(
                b.as_fd(),
                if cap == 3 { &mut [] } else { &mut buffer },
                if cap == 3 { 2 } else { cap },
                0,
            )
            .unwrap();
            println!(
                "{} {} {} {}",
                sent,
                msg.len,
                msg.fds.len(),
                u8::from(msg.truncated) + 2 * u8::from(msg.control_truncated)
            );
        }
        "token-extra" => {
            use peios::token::*;
            let sid = "SY".parse::<peios::security::Sid>().unwrap();
            let mut t = TokenBuilder::new();
            t.user(&sid);
            if arg == "empty" {
                for values in [
                    ClaimValues::Int64(vec![]),
                    ClaimValues::Uint64(vec![]),
                    ClaimValues::String(vec![]),
                    ClaimValues::Sid(vec![]),
                    ClaimValues::Boolean(vec![]),
                    ClaimValues::Octet(vec![]),
                ] {
                    t.add_user_claim(&Claim {
                        name: "empty".into(),
                        flags: ClaimAttr::empty(),
                        values,
                    });
                }
            } else {
                for _ in 0..arg.parse::<usize>().unwrap() {
                    t.add_group(&sid, 7);
                }
            }
            match t.to_bytes() {
                Ok(b) => dump(&b),
                Err(_) => println!("error"),
            }
        }
        "ring" => {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(arg)
                .unwrap();
            match peios::event::EventRing::map(f.into(), 256) {
                Err(_) => println!("error"),
                Ok(r) => {
                    let pos = r.tail_pos();
                    print!(
                        "{} {} {} {} ",
                        r.capacity(),
                        pos,
                        r.write_pos(),
                        r.generation()
                    );
                    r.set_need_wake(true);
                    r.set_need_wake(false);
                    match r.event_at(pos) {
                        Err(_) => println!("error"),
                        Ok((v, n)) => {
                            print!(
                                "{} {} {} ",
                                n,
                                v.sequence,
                                u8::from(r.wait(pos, 0).unwrap())
                            );
                            dump(v.payload);
                        }
                    }
                }
            }
        }
        "mp-cursor" => {
            use peios::msgpack::{Reader, Type};
            let (op, hex) = arg.split_once('|').unwrap();
            let b = unhex(hex);
            let mut r = Reader::new(&b);
            let k = match r.peek() {
                Some(Type::Nil) => 0,
                Some(Type::Bool) => 1,
                Some(Type::Int) => 2,
                Some(Type::Float) => 3,
                Some(Type::Str) => 4,
                Some(Type::Bin) => 5,
                Some(Type::Array) => 6,
                Some(Type::Map) => 7,
                Some(Type::Ext) => 8,
                None => -1,
            };
            let hexbytes = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
            let v = match op {
                "nil" => r.read_nil().map(|_| String::new()),
                "bool" => r.read_bool().map(|v| format!("{}", u8::from(v))),
                "int" => r.read_int().map(|v| v.to_string()),
                "uint" => r.read_uint().map(|v| v.to_string()),
                "float" => r.read_float().map(|v| format!("{:016x}", v.to_bits())),
                "str" => r.read_str().map(|v| hexbytes(v.as_bytes())),
                "bin" => r.read_bin().map(hexbytes),
                "ext" => r
                    .read_ext()
                    .map(|(typ, b)| format!("{typ}:{}", hexbytes(b))),
                "array" => r.read_array().map(|v| v.to_string()),
                "map" => r.read_map().map(|v| v.to_string()),
                "skip" => r.skip().map(|_| String::new()),
                _ => unreachable!(),
            };
            match v {
                Ok(v) => println!("{k} ok {} {v}", r.remaining()),
                Err(_) => println!("{k} error {}", r.remaining()),
            }
        }
        "mp-depth" => {
            let (depth, hex) = arg.split_once('|').unwrap();
            println!(
                "{}",
                if peios::msgpack::validate(&unhex(hex), depth.parse().unwrap()).is_ok() {
                    "ok"
                } else {
                    "error"
                }
            );
        }
        "sd-validate" => {
            println!(
                "{}",
                if peios::security::SdView::parse(&unhex(arg)).is_ok() {
                    "ok"
                } else {
                    "error"
                }
            );
        }
        "acl-validate" => {
            println!(
                "{}",
                if peios::security::AclView::parse(&unhex(arg)).is_ok() {
                    "ok"
                } else {
                    "error"
                }
            );
        }
        "mp-validate" => {
            println!(
                "{}",
                if peios::msgpack::validate(&unhex(arg), 32).is_ok() {
                    "ok"
                } else {
                    "error"
                }
            );
        }
        "audit-validate" => {
            println!(
                "{}",
                if peios::access::AuditContext::from_bytes(unhex(arg)).is_ok() {
                    "ok"
                } else {
                    "error"
                }
            );
        }
        "mp-fixture" => {
            let mut w = peios::msgpack::Writer::new();
            w.write_array(10)
                .write_nil()
                .write_bool(true)
                .write_int(-129)
                .write_uint(u64::MAX)
                .write_float(1.5)
                .write_str("hello")
                .write_bin(b"abc")
                .write_ext(-1, b"xy")
                .write_map(1)
                .write_str("n")
                .write_int(128)
                .write_array(0);
            dump(&w.to_bytes().unwrap());
        }
        "audit" => {
            match peios::access::AuditContext::new(
                arg,
                &[
                    ("name", "sdk".into()),
                    ("id", 300u64.into()),
                    ("ok", true.into()),
                ],
            ) {
                Ok(v) => dump(v.as_bytes()),
                Err(_) => println!("error"),
            }
        }
        "inherit" | "strip" => {
            use peios::file::SecInfo;
            use peios::security::sddl;
            let a: Vec<_> = arg.split('|').collect();
            let p = sddl::parse(a[0]).unwrap();
            let result = if mode == "strip" {
                sddl::strip_inherited(p.as_bytes(), SecInfo::DACL | SecInfo::SACL)
            } else {
                let c = sddl::parse(a[1]).unwrap();
                let m =
                    peios::security::GenericMapping::new(0x120089, 0x120116, 0x1200a0, 0x1f01ff);
                sddl::reinherit_with(
                    p.as_bytes(),
                    c.as_bytes(),
                    a[2] == "1",
                    Some(&m),
                    SecInfo::DACL | SecInfo::SACL,
                )
            };
            match result {
                Ok(v) => dump(v.as_bytes()),
                Err(_) => println!("error"),
            }
        }
        "token-spec" => {
            use peios::security::Privileges;
            use peios::token::*;
            let sid = "SY".parse::<peios::security::Sid>().unwrap();
            let mut t = TokenBuilder::new();
            t.user(&sid)
                .add_group(&sid, 7)
                .privileges(
                    Privileges::from_bits_retain(3),
                    Privileges::from_bits_retain(1),
                )
                .token_type(TokenType::Primary, ImpersonationLevel::Impersonation)
                .integrity(peios::security::IntegrityLevel::MEDIUM)
                .projected_ids(42, 43)
                .expiration(99)
                .source("sdk", 17)
                .supplementary_gids(&[1, 2]);
            if arg == "full" {
                t.add_device_group(&sid, 7)
                    .add_restricted_sid(&sid, 4)
                    .confinement(&sid)
                    .flags(TokenFlags {
                        write_restricted: true,
                        user_deny_only: true,
                        isolation_boundary: true,
                        confinement_exempt: true,
                    });
                let acl = peios::security::AclBuilder::new().build().unwrap();
                t.default_dacl(&acl);
                for values in [
                    ClaimValues::Int64(vec![-9]),
                    ClaimValues::Uint64(vec![300]),
                    ClaimValues::Boolean(vec![true]),
                    ClaimValues::String(vec!["hello".into()]),
                    ClaimValues::Sid(vec![sid.clone()]),
                    ClaimValues::Octet(vec![b"abc".to_vec()]),
                ] {
                    let c = Claim {
                        name: "claim".into(),
                        flags: ClaimAttr::empty(),
                        values,
                    };
                    t.add_user_claim(&c).add_device_claim(&c);
                }
                let mut scope = [0u8; 16];
                scope[0] = 1;
                t.lcs_credentials(&LcsCredentials {
                    scope_guids: vec![scope],
                    private_layers: vec!["private".into()],
                });
            };
            dump(&t.to_bytes().unwrap());
        }
        "native-access" => {
            use peios::security::{sddl, AccessMask, GenericMapping};
            let sd = sddl::parse(arg).unwrap();
            match peios::access::AccessCheck::new(
                &sd,
                AccessMask::from_bits_retain(1),
                GenericMapping::new(1, 2, 4, 7),
            )
            .check()
            {
                Ok(r) => println!("{} {}", u8::from(r.allowed), r.granted.bits()),
                Err(_) => println!("error"),
            }
        }
        _ => return false,
    };
    true
}
use peios::security::sddl;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    if extra(&args[1], &args[2]) {
        return;
    }
    if args[1] == "native-file" {
        use peios::file::SecInfo;
        let sd = peios::file::get_sd(
            None,
            std::path::Path::new(&args[2]),
            SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL,
            0,
        )
        .unwrap();
        for b in sd.as_bytes() {
            print!("{b:02x}");
        }
        println!();
        return;
    }
    if args[1] == "native-user" {
        let token =
            peios::token::Token::open_self(false, peios::token::TokenAccess::QUERY).unwrap();
        for b in token.user().unwrap().as_bytes() {
            print!("{b:02x}");
        }
        println!();
        return;
    }
    if args[1] == "sid" {
        match args[2].parse::<peios::security::Sid>() {
            Ok(s) => {
                for b in s.as_bytes() {
                    print!("{b:02x}");
                }
                println!("\n{s}");
            }
            Err(e) => println!("error {}", e.raw_os_error().unwrap_or(0)),
        }
        return;
    }
    let condition = args[1] == "condition";
    assert!(condition || args[1] == "sddl");
    let bytes = if condition {
        sddl::parse_condition(&args[2])
    } else {
        sddl::parse(&args[2]).map(|d| d.as_bytes().to_vec())
    };
    match bytes {
        Err(e) => println!("error {}", e.raw_os_error().unwrap_or(0)),
        Ok(b) => {
            for v in &b {
                print!("{v:02x}");
            }
            println!();
            let text = if condition {
                sddl::format_condition(&b)
            } else {
                sddl::format(&b)
            };
            match text {
                Ok(s) => println!("{s}"),
                Err(e) => println!("format-error {}", e.raw_os_error().unwrap_or(0)),
            }
        }
    }
}
