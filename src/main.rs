mod cli;
use cli::Args;
use std::io;
use std::fmt;
use clap::Parser;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use std::fs;
use std::path::PathBuf;
use tokio::net::TcpStream;
use std::sync::Arc;
use ipnet::IpNet;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::io::AsyncReadExt;
use std::str::FromStr;
use serde::Serialize;
use tabled::{settings::Style, Table, Tabled};


#[derive(Debug,Tabled,Serialize)]
struct ScanResult{
    #[tabled(rename = "HOST")]
    pub host: IpAddr,
    #[tabled(rename = "PORT")]
    pub port : u16,
    #[tabled(rename = "STATE")]
    pub state:PortState,
    #[tabled(rename = "BANNER", display_with = "format_banner")]
    pub banner: Option<String>
}



#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize)]
enum PortState{
    Open,Closed,Filtered
}

impl fmt::Display for PortState{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open=> write!(f,"Open"),
            PortState::Closed => write!(f,"Closed"),
            PortState::Filtered => write!(f,"Filtered"),

        }
        // write!()
    }
}

fn format_banner(banner: &Option<String>) -> String {
    banner.clone().unwrap_or_else(|| "".to_string())
}
async fn grab_banner(target: IpAddr, port:u16, timeout: Duration) -> Option<String>{
    let addr = SocketAddr::new(target,port);
    let stream = match tokio::time::timeout(timeout,TcpStream::connect(&addr)).await {
        Ok(Ok(stream))=> stream,
        _ => return None
    };
    let mut stream = stream;
    let mut buffer = vec![0;512];
    let read_results = tokio::time::timeout(timeout, stream.read(&mut buffer)).await;
    match read_results {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
            Some(banner)
        },
        _=> None
    }

}
 async fn scan_port(target_ip: IpAddr, port: u16, timeout:Duration,grab_banners: bool)-> ScanResult{
     let socket_addr = SocketAddr::new(target_ip, port);
     let connection_attempt = tokio::time::timeout(timeout,TcpStream::connect(&socket_addr)).await;
     let (state , should_grab_banner) = match  connection_attempt {
         Ok(Ok(_))=>
             (PortState::Open,true)
         ,
         Ok(Err(e))=>{
             if e.kind() == io::ErrorKind::ConnectionRefused{
                 ( PortState::Closed, false)
             }else{
                 (PortState::Filtered, false)
             }
         },
         Err(_)=> (PortState::Filtered,false)

     };

     let banner = if grab_banners && should_grab_banner{
            grab_banner(target_ip,port,timeout).await
     }else{
         None
     };
     ScanResult{
         host:target_ip,
         port,
         state,
         banner
     }

 }

  fn resolve_targets(target_str: &str)->Result<Vec<IpAddr>, String>{
        if target_str.contains('/'){
            match IpNet::from_str(target_str){
                Ok(ip_net) => {
                    let hosts : Vec<IpAddr> = ip_net.hosts().collect();
                    if hosts.is_empty(){
                        Err(format!("CIDR block :{} contains no usable host address.",target_str))
                    }else{
                        Ok(hosts)
                    }
                },
                Err(e) => {
                    Err(format!("Error parsing CIDR block : '{}' {}", target_str, e))
                }
            }
        }else {
            match (target_str, 0).to_socket_addrs(){
                Ok(iter)=> {
                    let addrs :Vec<IpAddr> = iter.map(|sa| sa.ip()).collect();
                        if addrs.is_empty(){
                            Err(format!("Could not resolve hostname '{}'  to  any IP addresses.", target_str))

                        }else{
                            Ok(addrs)
                        }

                },
                Err(e)=> Err(format!("Error: Could not resolve hostname: '{}' ", target_str)),

            }
        }
 }

fn write_results_to_json(file_path : &PathBuf, results: &[ScanResult] ) -> Result<(),std::io::Error>{
    let json_output = serde_json::to_string_pretty(results)?;
    fs::write(file_path,json_output)?;
    println!("\nScan results written to {}", file_path.display());
    Ok(())
}
#[tokio::main]
async fn main() {
    let args = Args::parse();

    let ports = match cli::parse_ports(&args.ports){
        Ok(ports)=> ports,
        Err(e)=>{
            eprintln!("Error parsing port range: {}",e);
            std::process::exit(1);
        }
    };

    let target_ips = match resolve_targets(&args.target){
        Ok(ips) => ips,
        Err(e)=>{
            eprintln!("{}",e);
            std::process::exit(1);
        }
    };

    //
    // let socket_address: Vec<SocketAddr> = match format!("{}:0", args.target).to_socket_addrs(){
    //
    //         Ok(Iterator)=>  Iterator.collect(),
    //         Err(_) => {
    //             eprintln!("Error: could not resolve host name :{}", args.target);
    //             return;
    //         }
    // };
    //
    // if socket_address.is_empty(){
    //     eprintln!("Error: No IP address found for '{}'", args.target);
    // }
    //
    // let target_ip = socket_address[0].ip();
    // println!("Scanning target: {} (ports {})", target_ip,args.ports);


    let timeout = Duration::from_millis(args.timeout);

    const CONCURRENCY:usize = 100;
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut tasks: Vec<JoinHandle<ScanResult>> = vec![];

    for target_ip in target_ips {
    for port in &ports {
        let port = *port;
        let sem_clone =Arc::clone(&semaphore);
        let grab_banner = args.banners;

        let task = tokio::spawn(async move {
            let _permit = sem_clone.acquire_owned().await.unwrap();
            scan_port(target_ip, port, timeout,args.banners).await
        });
        tasks.push(task)
    }
    }

    let  mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    results.sort_by_key(|r| (r.host, r.port));


    // println!("\nScan results:");
    // for result in &results {
    //     if result.state == PortState::Open{
    //        let banner_text = result.banner.as_deref().unwrap_or("");
    //         println!(
    //             "{:<15} {:<5} {:<8} {}",
    //             result.host,
    //             result.port,
    //             result.state.to_string(),
    //             banner_text
    //         );
    //     }
    //
    // }


    let open_ports: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.state == PortState::Open)
        .collect();


    if !open_ports.is_empty(){
        println!("\n Scan result (Open ports)");
        let mut table = Table::new(open_ports);
        table.with(Style::modern());
        println!("{} :", table);

    }else{
        println!("\n Scan complete. No open port found.");
    }

    if let Some(file_path) = args.json{
        match write_results_to_json(&file_path , &results){
            Ok(_)=> {},
            Err(e) => eprintln!("Error writing to JSON file: {}", e),
        }
    }

}


