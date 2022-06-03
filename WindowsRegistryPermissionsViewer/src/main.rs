extern crate windows_acl;
extern crate windows;

use std::io;
use std::io::Error;
use std::slice;

use windows_acl::acl::{
    ACL, 
    ACLEntry
};

use windows_acl::helper::{
    current_user,
    string_to_sid,
};

// ~ Registry ACL flags/masks ~
// https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
// "The valid access rights for registry keys include the DELETE, READ_CONTROL, WRITE_DAC, and 
// WRITE_OWNER standard access rights."
use windows::Win32::System::SystemServices::{
    DELETE,
    WRITE_DAC, 
    WRITE_OWNER,
};
use windows::Win32::Storage::FileSystem::{
    READ_CONTROL,
    SYNCHRONIZE, // "Registry keys do not support the SYNCHRONIZE standard access right."
    STANDARD_RIGHTS_READ,
    STANDARD_RIGHTS_WRITE,
    STANDARD_RIGHTS_EXECUTE,
    STANDARD_RIGHTS_ALL,
    SPECIFIC_RIGHTS_ALL,
};
use windows::Win32::System::Registry::{
    KEY_ALL_ACCESS, // "Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights."
    KEY_CREATE_LINK, // "Reserved for system use."
    KEY_CREATE_SUB_KEY,
    KEY_ENUMERATE_SUB_KEYS,
    KEY_EXECUTE, // "Equivalent to KEY_READ."
    KEY_NOTIFY,
    KEY_QUERY_VALUE,
    KEY_READ,
    KEY_WOW64_32KEY,
    KEY_WOW64_64KEY,
    KEY_WRITE,
};
use windows::Win32::System::SystemServices::{
    GENERIC_ALL,
    GENERIC_READ,
    GENERIC_WRITE,
    GENERIC_EXECUTE,
};


// Useful API calls
use windows::Win32::Security::{
    SID_NAME_USE,
    SidTypeUser,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel,
    SidTypeLogonSession,
    LookupAccountSidW,
};

use windows::Win32::Security::Authorization::ConvertStringSidToSidW;

use windows::Win32::Foundation::{
    PSID,
    BOOL,
};
use windows::Win32::Security::{
    SID
};
use windows::core::{
    PWSTR,
};

fn sid_to_name(stringsid: &str) -> String {
    
    // First convert the string SID to a SID structure.
    let sid: *mut PSID = &mut PSID::default();
    let result: BOOL = unsafe { ConvertStringSidToSidW(stringsid, sid) };
    
    if result == false
    {
        let os_error = Error::last_os_error();
        panic!("Windows error doing ConvertStringSidToSidW: {os_error:?}.")
    };

    let lpsystemname = "";

    let mut name_buffer = Vec::<u16>::with_capacity(256);
    let name = PWSTR(name_buffer.as_mut_ptr());
    let cchname: *mut u32 = &mut 256;

    let mut refdomain_buffer = Vec::<u16>::with_capacity(256);
    let refdomain = PWSTR(refdomain_buffer.as_mut_ptr());
    let cchrefdomain: *mut u32 = &mut 256;
    
    let sid_name_use: *mut SID_NAME_USE = &mut SID_NAME_USE::default();

    let result: BOOL = unsafe {
        LookupAccountSidW(
            lpsystemname,
            *sid, 
            name,
            cchname,
            refdomain,
            cchrefdomain,
            sid_name_use
        )
    };

    let user_name: String = if result == false {
        let os_error = Error::last_os_error();
        match os_error.raw_os_error() {
            Some(1332) => println!("Windows ERROR_NONE_MAPPED doing LookupAccountSidW: {os_error:?}."),
            Some(i32::MIN..=1331_i32) => println!("Unexpected Windows error doing LookupAccountSidW: {os_error:?}."),
            Some(1333_i32..=i32::MAX) => println!("Unexpected Windows error doing LookupAccountSidW: {os_error:?}."),
            None => println!("Windows error doing LookupAccountSidW, but couldn't get error code.")
        };
        String::new()
    } else {
        let buffer = unsafe { slice::from_raw_parts(name.0, *cchname as usize) };
        String::from_utf16_lossy(&buffer)
    };

    let sid_name_use: SID_NAME_USE = unsafe { *sid_name_use };
    let acc_type: &str = match sid_name_use {
        SID_NAME_USE(i32::MIN..=0_i32)    => "UNKNOWN",
        SidTypeUser         => "SidTypeUser", // 1
        SidTypeGroup        => "SidTypeGroup",
        SidTypeDomain       => "SidTypeDomain",
        SidTypeAlias        => "SidTypeAlias",
        SidTypeWellKnownGroup=> "SidTypeWellKnownGroup",
        SidTypeDeletedAccount=> "SidTypeDeletedAccount",
        SidTypeInvalid      => "SidTypeInvalid",
        SidTypeUnknown      => "SidTypeUnknown",
        SidTypeComputer     => "SidTypeComputer",
        SidTypeLabel        => "SidTypeLabel",
        SidTypeLogonSession => "SidTypeLogonSession",
        SID_NAME_USE(12_i32..=i32::MAX)   => "UNKNOWN",
    };

    println!("Username: \"{}\" ({:?})", user_name, acc_type);

    user_name

}

// https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format


// ACE Strings: https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings


// https://securityboulevard.com/2018/08/introducing-windows-acl-working-with-acls-in-rust/

// ACL uses GetNamedSecurityInfoW under the hood, so if we're querying the registry, we need to 
// pass it in a way that SE_REGISTRY_KEY is expecting 
// 
//      "The names of registry keys must use the following literal strings to identify the 
//      predefined registry keys: "CLASSES_ROOT", "CURRENT_USER", "MACHINE", and "USERS"."
//      - (https://docs.microsoft.com/en-us/windows/win32/api/accctrl/ne-accctrl-se_object_type)

fn main() -> io::Result<()> {

    let this_user = windows_acl::helper::current_user();

    match this_user {
        Some(user) => println!("Starting up, running as {}", user),
        None => ()
    }
    
    // let HKEY_CLASSES_ROOT = "CLASSES_ROOT";
    // let HKEY_CURRENT_USER = "CURRENT_USER";
    // let HKEY_LOCAL_MACHINE = "MACHINE";
    // let HKEY_USERS = "USERS";
    // let HKEY_CURRENT_CONFIG = "CURRENT_CONFIG"; // ? Is this right?

    let path = "MACHINE\\SYSTEM\\CurrentControlSet\\Services";

    let acl = ACL::from_registry_path(path, false, false);

    let acl = match acl {
        Ok(acl) => acl,
        Err(error) => {
            let os_error = Error::last_os_error();
            panic!("Windows error code {error}: {os_error:?}.")
        }
    };

    println!("{:?}", acl);

    let all_entries = acl.all();

    let all_entries: Vec<ACLEntry> = match all_entries {
        Ok(acl) => acl,
        Err(error) => {
            panic!("Error getting ACLEntries: {error}.")
        }
    };

    for e in all_entries
    {
        println!(
            "({}) Type: {} - AceSize: 0x{:x}, AceFlags: 0x{:x}, ACCESS_MASK: 0x{:x}, SID string: {}", 
            e.index, 
            e.entry_type, 
            e.size, 
            e.flags, 
            e.mask, // https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
            e.string_sid
        );

        let raw_sid = string_to_sid(&e.string_sid);
        println!("raw_sid: {:?}, string sid: {}", raw_sid, e.string_sid);

        sid_to_name(&e.string_sid);

        if (e.mask & DELETE) != 0                       { println!("DELETE") };
        if (e.mask & WRITE_DAC) != 0                    { println!("WRITE_DAC") };
        if (e.mask & WRITE_OWNER) != 0                  { println!("WRITE_OWNER") };
        
        if (e.mask & READ_CONTROL.0) != 0               { println!("READ_CONTROL") };
        if (e.mask & SYNCHRONIZE.0) != 0                { println!("SYNCHRONIZE - very unexpected!") };
        if (e.mask & STANDARD_RIGHTS_READ.0) != 0       { println!("STANDARD_RIGHTS_READ") };
        if (e.mask & STANDARD_RIGHTS_WRITE.0) != 0      { println!("STANDARD_RIGHTS_WRITE") };
        if (e.mask & STANDARD_RIGHTS_EXECUTE.0) != 0    { println!("STANDARD_RIGHTS_EXECUTE") };
        if (e.mask & STANDARD_RIGHTS_ALL.0) != 0        { println!("STANDARD_RIGHTS_ALL") };
        if (e.mask & SPECIFIC_RIGHTS_ALL.0) != 0        { println!("SPECIFIC_RIGHTS_ALL") };
        
        // Generics
        if (e.mask & GENERIC_ALL) != 0                  { println!("GENERIC_ALL") };
        if (e.mask & GENERIC_READ) != 0                 { println!("GENERIC_READ") };
        if (e.mask & GENERIC_WRITE) != 0                { println!("GENERIC_WRITE") };
        if (e.mask & GENERIC_EXECUTE) != 0              { println!("GENERIC_EXECUTE") };

        // Start specific registry masks
        if (e.mask & KEY_ALL_ACCESS.0) != 0             { println!("KEY_ALL_ACCESS") };
        if (e.mask & KEY_CREATE_LINK.0) != 0            { println!("KEY_CREATE_LINK") };
        if (e.mask & KEY_CREATE_SUB_KEY.0) != 0         { println!("KEY_CREATE_SUB_KEY") };
        if (e.mask & KEY_ENUMERATE_SUB_KEYS.0) != 0     { println!("KEY_ENUMERATE_SUB_KEYS") };
        if (e.mask & KEY_EXECUTE.0) != 0                { println!("KEY_EXECUTE (equivalient to KEY_READ)") };
        if (e.mask & KEY_NOTIFY.0) != 0                 { println!("KEY_NOTIFY") };
        if (e.mask & KEY_QUERY_VALUE.0) != 0            { println!("KEY_QUERY_VALUE") };
        if (e.mask & KEY_READ.0) != 0                   { println!("KEY_READ") };
        if (e.mask & KEY_WOW64_32KEY.0) != 0            { println!("KEY_WOW64_32KEY") };
        if (e.mask & KEY_WOW64_64KEY.0) != 0            { println!("KEY_WOW64_64KEY") };
        if (e.mask & KEY_WRITE.0) != 0                  { println!("KEY_WRITE") };   
    }

    Ok(())
}
