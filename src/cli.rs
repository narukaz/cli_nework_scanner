use clap::Parser;
use std::path::PathBuf;


#[derive(Parser,Debug)]
#[command(author,version,about,long_about = None)]
pub struct Args{
    /// The target to scan (IP address or hostname)
    pub target: String,
    /// The port range to scan (e.g., "1-1024", "80,443", or "1-100,8080")
    #[arg(short='p', long,default_value="1-1024")]
    pub ports: String,
    /// The number of concurrent scanning threads to use
    #[arg(short = 't', long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=5000) )]
    pub threads: u16,
    /// The timeout in milliseconds for each port scan
    #[arg(short = 'm', long, default_value_t = 5000)]
    pub timeout: u64,
    #[arg(long)]
    pub banners: bool,
    #[arg(long, default_value_t = 100)]
    pub concurrency:usize,
    #[arg(long)]
    pub json: Option<PathBuf>
}

pub fn parse_ports(port_arg:&str)->Result<Vec<u16>,String>{
    let mut ports = Vec::new();
    for part in port_arg.split(','){
            let trimmed_part = part.trim();
            if trimmed_part.contains("-"){
                let range: Vec<&str> = trimmed_part.split("-").collect();
                if range.len() != 2{
                    return Err(format!("Invalid port range: {}",trimmed_part));
                }
                let start:u16 = range[0].parse().map_err(|_| format!("Invalid Port range start: {}",range[0]))?;
                let end:u16 = range[1].parse().map_err(|_| format!("Invalid Port range end: {}",range[0]))?;
                if start > end {
                    return Err(format!("Start port must be less than or equal to end port: {}", trimmed_part));
                }
                for port in start..=end {
                    ports.push(port);

                }

            }else{
                let port: u16 = trimmed_part.parse().map_err(|_| format!("Invalid port: {}", trimmed_part))?;
                ports.push(port);
            }
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)


}