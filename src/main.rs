// example application

// https://www.grc.com/sqrl/diag.htm
pub fn main() {
    let test: &[u8] = b"\
        SQRLDATAfQABAC0AwDR2aKohNUWypIv-Y6TeUWbko_arcPwMB9alpAkEAAAA8QAEAQ8A7uDR\
        pBDxqJZxwUkB4y9-p5XWvAbgVMK02lvnSA_-EBHjLarjoHYdb-UEVW2rC4z2URyOcxpCeQXf\
        GpZQyuZ3dSGiuIFI1eLFX-xnsRsRBdtJAAIAoiMr93uN8ylhOHzwlPmfVAkUAAAATne7wOsR\
        jUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLfD_Gul4vRyrMC2pn7UBaV9lgADAAQABBIcrU-W\
        RSyG8So14IuJuYmBC-95QWs9uDhs26TjsUCPl1SBpr99CgP8oyLXtneMMX7V8KqipjcZHDFp\
        b4PNi0Qg5EHYCxElSBla-Jl7xqdstQ_l0q3WvQvIOlMJNw2bM-99urzL7snuvc4fs-Uo6kas\
        ACzYLDUYVveXqEM8NrmAMqz3QAaJfCCpQPv_uowE";
    let s4 = libsqrl::storage::S4::new(test);
    dbg!(s4);

    let url = "sqrl://sqrl.grc.com/cli.sqrl?nut=e23CL6ueIaHU&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw";
    let client = libsqrl::client::Client::new();
    client.open(url);
}
