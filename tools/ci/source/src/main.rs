use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [command, root] if command == "tls-revision" => {
            let identity = hibana_quic_source_check::Identity::read(Path::new(root))?;
            println!("revision={}", identity.tls_revision);
        }
        [command, root] if command == "audit" => {
            hibana_quic_source_check::audit_pair(Path::new(root))?;
        }
        [command, root] if command == "dependencies" => {
            hibana_quic_source_check::check_dependencies(Path::new(root))?;
        }
        [command, root, output] if command == "stage" => {
            hibana_quic_source_check::stage(Path::new(root), Path::new(output))?;
        }
        _ => {
            return Err(
                "usage: source-check {tls-revision|audit|dependencies} ROOT | stage ROOT OUTPUT"
                    .into(),
            );
        }
    }
    Ok(())
}
