rule encrypted_c2_beacon {
    meta:
        author = "Your Name"
        date = "2023-08-20"
        description = "Detects encrypted C2 beacon patterns"
    
    strings:
        $magic = { DE AD BE EF }
        $size_check = "session=" wide ascii
        $data_field = "data=" wide ascii
    
    condition:
        ($magic at 0) and 
        ($size_check and $data_field) and 
        filesize > 128KB
}