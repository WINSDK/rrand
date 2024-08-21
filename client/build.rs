fn main() {
    cc::Build::new()
        .file("tlv/threadLocalVariables.c")
        .file("tlv/threadLocalHelpers.s")
        .include("xnu-7195.81.3/osfmk/")
        .compile("threadLocalHelpers");
}
