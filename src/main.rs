// example application

pub fn main() {
    let url = "sqrl://sqrl.grc.com/cli.sqrl?nut=testnut&can=something";
    let client = libsqrl::client::Client::new();
    client.open(url);
}
