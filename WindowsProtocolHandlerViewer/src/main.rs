extern crate winreg;
use std::io;
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;
use winreg::RegValue;
use log::{info, warn};

/*
WindowsProtocolHanderViewer
Tool to see all active protocol handers/schemas on the system.
*/


// URL handlers can be found at:
// HKEY_CURRENT_USER\SOFTWARE\Classes\*
// HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*
// HKEY_CLASSES_ROOT\*


// fn print_subkeys(regkey: &RegKey)
// {
//     for key in regkey.enum_keys().map(|x| x.unwrap()) {
//         println!("Key: {}", key)
//     }
// }

// fn print_values(regkey: &RegKey)
// {
//     for (mut name, value) in regkey.enum_values().map(|x| x.unwrap())
//         {
//             if name == ""
//             {
//                 name = "(Default)".to_owned();
//             }
//             println!("{} = {:?}", name, value);
//         }
// }


// fn get_values(key: &RegKey) -> Vec<String>
// {
    
// }
struct URLProtocol {
    name: String,
    command_line: String,
}

fn main() -> io::Result<()> {
    
    // Collect everything into the url_protocol_list
    let mut url_protocol_list: Vec<URLProtocol> = Vec::new();

    println!("Reading all the HKEY_CLASSES_ROOT subkeys");
    let hkey_root = RegKey::predef(HKEY_CLASSES_ROOT);

    let hkey_root_subkeys: Vec<String> = hkey_root
        .enum_keys()
        .map(|x| x.unwrap())
        .collect();

    for hkey_root_subkey in &hkey_root_subkeys 
    {
        // println!("ROOT KEY: {:?}", hkey_root_subkey);

        let key = hkey_root.open_subkey(hkey_root_subkey)?;
        
        let values: Vec<(String, RegValue)> = key
            .enum_values()
            .map(|x| x.unwrap())
            .collect();
        
        for tuple in values {
            let (value, _data) = tuple;

            if value == "URL Protocol"
            // This should be a URL scheme definition!
            {
                let path = Path::new(hkey_root_subkey).join("shell\\open\\command");
                let shell_open_command = hkey_root.open_subkey(path);
                
                let shell_open_command_key: RegKey = match shell_open_command {
                    Ok(key) => key,
                    Err(error) => {
                        warn!("Couldn't open {}\\shell\\open\\command key: {}", &hkey_root_subkey, error);
                        continue
                    }
                };

                let shell_value = shell_open_command_key.get_value("");

                let shell_command_line_value: String = match shell_value {
                    Ok(val) => val,
                    Err(error) => {
                        warn!("Couldn't read {}\\shell\\open\\command value: {:?}", &hkey_root_subkey, error);
                        continue
                    }
                };
                
                println!("{} = {}", hkey_root_subkey, shell_command_line_value);

                let this_url_protocol = URLProtocol {
                    name: String::from(hkey_root_subkey),
                    command_line: String::from(shell_command_line_value),
                }; 

                url_protocol_list.push(this_url_protocol)
            }
        }
        // print_subkeys(&key);
        // print_values(&key);
        // println!("")
    }

    // let system = RegKey::predef(HKEY_LOCAL_MACHINE)
    //     .open_subkey("HARDWARE\\DESCRIPTION\\System")?;
    // for (name, value) in system.enum_values().map(|x| x.unwrap()) {
    //     println!("{} = {:?}", name, value);
    // }

    Ok(())

}