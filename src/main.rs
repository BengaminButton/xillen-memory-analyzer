use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::process;
use tokio;
use tracing::{error, info, warn};

mod analyzer;
mod crypto;
mod forensics;
mod memory;
mod process;
mod scanner;
mod utils;

use analyzer::MemoryAnalyzer;
use forensics::ForensicsEngine;
use memory::MemoryManager;
use process::ProcessAnalyzer;
use scanner::MemoryScanner;
use utils::{config::Config, output::OutputManager};

#[derive(Parser)]
#[command(
    name = "xillen-memory-analyzer",
    about = "Advanced memory analysis and forensics tool",
    version = "1.0.0",
    author = "@Bengamin_Button"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, default_value = "config.json")]
    config: PathBuf,
    
    #[arg(short, long)]
    verbose: bool,
    
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze live memory of running processes
    Live {
        #[arg(short, long)]
        pid: Option<u32>,
        
        #[arg(short, long)]
        process_name: Option<String>,
        
        #[arg(short, long, default_value = "100")]
        sample_size: usize,
    },
    
    /// Analyze memory dump files
    Dump {
        #[arg(short, long)]
        file: PathBuf,
        
        #[arg(short, long)]
        format: Option<String>,
        
        #[arg(short, long)]
        offset: Option<u64>,
        
        #[arg(short, long)]
        size: Option<usize>,
    },
    
    /// Scan memory for specific patterns
    Scan {
        #[arg(short, long)]
        pattern: String,
        
        #[arg(short, long)]
        regex: bool,
        
        #[arg(short, long)]
        case_sensitive: bool,
        
        #[arg(short, long)]
        max_results: Option<usize>,
    },
    
    /// Perform forensics analysis
    Forensics {
        #[arg(short, long)]
        target: PathBuf,
        
        #[arg(short, long)]
        artifacts: bool,
        
        #[arg(short, long)]
        timeline: bool,
        
        #[arg(short, long)]
        report: Option<PathBuf>,
    },
    
    /// Encrypt/decrypt memory regions
    Crypto {
        #[arg(short, long)]
        action: String,
        
        #[arg(short, long)]
        algorithm: String,
        
        #[arg(short, long)]
        key: Option<String>,
        
        #[arg(short, long)]
        input: PathBuf,
        
        #[arg(short, long)]
        output: PathBuf,
    },
    
    /// Process analysis and enumeration
    Process {
        #[arg(short, long)]
        list: bool,
        
        #[arg(short, long)]
        info: Option<u32>,
        
        #[arg(short, long)]
        modules: Option<u32>,
        
        #[arg(short, long)]
        handles: Option<u32>,
    },
    
    /// Memory region analysis
    Regions {
        #[arg(short, long)]
        pid: Option<u32>,
        
        #[arg(short, long)]
        detailed: bool,
        
        #[arg(short, long)]
        permissions: bool,
        
        #[arg(short, long)]
        protection: bool,
    },
    
    /// String extraction from memory
    Strings {
        #[arg(short, long)]
        target: PathBuf,
        
        #[arg(short, long, default_value = "4")]
        min_length: usize,
        
        #[arg(short, long)]
        encoding: Option<String>,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Network connection analysis
    Network {
        #[arg(short, long)]
        pid: Option<u32>,
        
        #[arg(short, long)]
        connections: bool,
        
        #[arg(short, long)]
        sockets: bool,
        
        #[arg(short, long)]
        dns: bool,
    },
    
    /// Registry analysis (Windows)
    Registry {
        #[arg(short, long)]
        hives: bool,
        
        #[arg(short, long)]
        keys: Vec<String>,
        
        #[arg(short, long)]
        values: bool,
        
        #[arg(short, long)]
        timeline: bool,
    },
    
    /// File system analysis
    Filesystem {
        #[arg(short, long)]
        target: PathBuf,
        
        #[arg(short, long)]
        deleted: bool,
        
        #[arg(short, long)]
        slack: bool,
        
        #[arg(short, long)]
        metadata: bool,
    },
    
    /// Malware detection and analysis
    Malware {
        #[arg(short, long)]
        target: PathBuf,
        
        #[arg(short, long)]
        signatures: bool,
        
        #[arg(short, long)]
        behavior: bool,
        
        #[arg(short, long)]
        yara: Option<PathBuf>,
        
        #[arg(short, long)]
        quarantine: Option<PathBuf>,
    },
    
    /// Memory integrity checking
    Integrity {
        #[arg(short, long)]
        baseline: Option<PathBuf>,
        
        #[arg(short, long)]
        current: Option<PathBuf>,
        
        #[arg(short, long)]
        checksums: bool,
        
        #[arg(short, long)]
        signatures: bool,
    },
    
    /// Performance profiling
    Profile {
        #[arg(short, long)]
        duration: Option<u64>,
        
        #[arg(short, long)]
        interval: Option<u64>,
        
        #[arg(short, long)]
        metrics: Vec<String>,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Generate comprehensive report
    Report {
        #[arg(short, long)]
        target: PathBuf,
        
        #[arg(short, long)]
        format: Option<String>,
        
        #[arg(short, long)]
        template: Option<PathBuf>,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    if cli.verbose {
        tracing_subscriber::fmt::init();
    }
    
    let config = Config::load(&cli.config)?;
    let output_manager = OutputManager::new(cli.output.clone());
    
    let progress_bar = ProgressBar::new_spinner();
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
    );
    
    info!("Starting XILLEN Memory Analyzer v1.0.0");
    
    match cli.command {
        Commands::Live { pid, process_name, sample_size } => {
            progress_bar.set_message("Analyzing live memory...");
            
            let analyzer = MemoryAnalyzer::new(config.clone());
            let result = analyzer.analyze_live_memory(pid, process_name, sample_size).await?;
            
            progress_bar.finish_with_message("Live memory analysis completed");
            output_manager.save_result(&result, "live_analysis")?;
            
            println!("{}", "Live Memory Analysis Results".green().bold());
            println!("{}", result);
        }
        
        Commands::Dump { file, format, offset, size } => {
            progress_bar.set_message("Analyzing memory dump...");
            
            let analyzer = MemoryAnalyzer::new(config.clone());
            let result = analyzer.analyze_memory_dump(&file, format, offset, size).await?;
            
            progress_bar.finish_with_message("Memory dump analysis completed");
            output_manager.save_result(&result, "dump_analysis")?;
            
            println!("{}", "Memory Dump Analysis Results".green().bold());
            println!("{}", result);
        }
        
        Commands::Scan { pattern, regex, case_sensitive, max_results } => {
            progress_bar.set_message("Scanning memory for patterns...");
            
            let scanner = MemoryScanner::new(config.clone());
            let result = scanner.scan_pattern(&pattern, regex, case_sensitive, max_results).await?;
            
            progress_bar.finish_with_message("Pattern scanning completed");
            output_manager.save_result(&result, "pattern_scan")?;
            
            println!("{}", "Pattern Scan Results".green().bold());
            println!("{}", result);
        }
        
        Commands::Forensics { target, artifacts, timeline, report } => {
            progress_bar.set_message("Performing forensics analysis...");
            
            let forensics = ForensicsEngine::new(config.clone());
            let result = forensics.analyze(&target, artifacts, timeline).await?;
            
            progress_bar.finish_with_message("Forensics analysis completed");
            
            if let Some(report_path) = report {
                forensics.generate_report(&result, &report_path).await?;
                println!("{}", format!("Report saved to: {}", report_path.display()).green());
            }
            
            output_manager.save_result(&result, "forensics_analysis")?;
            
            println!("{}", "Forensics Analysis Results".green().bold());
            println!("{}", result);
        }
        
        Commands::Crypto { action, algorithm, key, input, output } => {
            progress_bar.set_message("Processing cryptographic operation...");
            
            let crypto_engine = crypto::CryptoEngine::new(config.clone());
            let result = match action.as_str() {
                "encrypt" => crypto_engine.encrypt(&algorithm, &key, &input, &output).await?,
                "decrypt" => crypto_engine.decrypt(&algorithm, &key, &input, &output).await?,
                _ => return Err("Invalid action. Use 'encrypt' or 'decrypt'".into()),
            };
            
            progress_bar.finish_with_message("Cryptographic operation completed");
            output_manager.save_result(&result, "crypto_operation")?;
            
            println!("{}", "Cryptographic Operation Results".green().bold());
            println!("{}", result);
        }
        
        Commands::Process { list, info, modules, handles } => {
            progress_bar.set_message("Analyzing processes...");
            
            let process_analyzer = ProcessAnalyzer::new(config.clone());
            
            if list {
                let processes = process_analyzer.list_processes().await?;
                println!("{}", "Running Processes".green().bold());
                for process in processes {
                    println!("{}", process);
                }
            }
            
            if let Some(pid) = info {
                let info = process_analyzer.get_process_info(pid).await?;
                println!("{}", format!("Process Info for PID {}", pid).green().bold());
                println!("{}", info);
            }
            
            if let Some(pid) = modules {
                let modules = process_analyzer.get_process_modules(pid).await?;
                println!("{}", format!("Modules for PID {}", pid).green().bold());
                for module in modules {
                    println!("{}", module);
                }
            }
            
            if let Some(pid) = handles {
                let handles = process_analyzer.get_process_handles(pid).await?;
                println!("{}", format!("Handles for PID {}", pid).green().bold());
                for handle in handles {
                    println!("{}", handle);
                }
            }
            
            progress_bar.finish_with_message("Process analysis completed");
        }
        
        Commands::Regions { pid, detailed, permissions, protection } => {
            progress_bar.set_message("Analyzing memory regions...");
            
            let memory_manager = MemoryManager::new(config.clone());
            let regions = memory_manager.analyze_regions(pid, detailed, permissions, protection).await?;
            
            progress_bar.finish_with_message("Memory regions analysis completed");
            output_manager.save_result(&regions, "memory_regions")?;
            
            println!("{}", "Memory Regions Analysis".green().bold());
            for region in regions {
                println!("{}", region);
            }
        }
        
        Commands::Strings { target, min_length, encoding, output } => {
            progress_bar.set_message("Extracting strings from memory...");
            
            let scanner = MemoryScanner::new(config.clone());
            let strings = scanner.extract_strings(&target, min_length, encoding).await?;
            
            progress_bar.finish_with_message("String extraction completed");
            
            if let Some(output_path) = output {
                std::fs::write(&output_path, strings.join("\n"))?;
                println!("{}", format!("Strings saved to: {}", output_path.display()).green());
            }
            
            output_manager.save_result(&strings, "extracted_strings")?;
            
            println!("{}", "Extracted Strings".green().bold());
            println!("Found {} strings", strings.len());
            for string in strings.iter().take(100) {
                println!("{}", string);
            }
            if strings.len() > 100 {
                println!("... and {} more strings", strings.len() - 100);
            }
        }
        
        Commands::Network { pid, connections, sockets, dns } => {
            progress_bar.set_message("Analyzing network activity...");
            
            let analyzer = MemoryAnalyzer::new(config.clone());
            let network_info = analyzer.analyze_network(pid, connections, sockets, dns).await?;
            
            progress_bar.finish_with_message("Network analysis completed");
            output_manager.save_result(&network_info, "network_analysis")?;
            
            println!("{}", "Network Analysis Results".green().bold());
            println!("{}", network_info);
        }
        
        Commands::Registry { hives, keys, values, timeline } => {
            progress_bar.set_message("Analyzing registry...");
            
            let forensics = ForensicsEngine::new(config.clone());
            let registry_info = forensics.analyze_registry(hives, &keys, values, timeline).await?;
            
            progress_bar.finish_with_message("Registry analysis completed");
            output_manager.save_result(&registry_info, "registry_analysis")?;
            
            println!("{}", "Registry Analysis Results".green().bold());
            println!("{}", registry_info);
        }
        
        Commands::Filesystem { target, deleted, slack, metadata } => {
            progress_bar.set_message("Analyzing file system...");
            
            let forensics = ForensicsEngine::new(config.clone());
            let fs_info = forensics.analyze_filesystem(&target, deleted, slack, metadata).await?;
            
            progress_bar.finish_with_message("File system analysis completed");
            output_manager.save_result(&fs_info, "filesystem_analysis")?;
            
            println!("{}", "File System Analysis Results".green().bold());
            println!("{}", fs_info);
        }
        
        Commands::Malware { target, signatures, behavior, yara, quarantine } => {
            progress_bar.set_message("Performing malware analysis...");
            
            let forensics = ForensicsEngine::new(config.clone());
            let malware_info = forensics.analyze_malware(&target, signatures, behavior, yara, quarantine).await?;
            
            progress_bar.finish_with_message("Malware analysis completed");
            output_manager.save_result(&malware_info, "malware_analysis")?;
            
            println!("{}", "Malware Analysis Results".green().bold());
            println!("{}", malware_info);
        }
        
        Commands::Integrity { baseline, current, checksums, signatures } => {
            progress_bar.set_message("Checking memory integrity...");
            
            let analyzer = MemoryAnalyzer::new(config.clone());
            let integrity_info = analyzer.check_integrity(baseline, current, checksums, signatures).await?;
            
            progress_bar.finish_with_message("Integrity check completed");
            output_manager.save_result(&integrity_info, "integrity_check")?;
            
            println!("{}", "Memory Integrity Check Results".green().bold());
            println!("{}", integrity_info);
        }
        
        Commands::Profile { duration, interval, metrics, output } => {
            progress_bar.set_message("Profiling memory performance...");
            
            let analyzer = MemoryAnalyzer::new(config.clone());
            let profile_data = analyzer.profile_performance(duration, interval, &metrics).await?;
            
            progress_bar.finish_with_message("Performance profiling completed");
            
            if let Some(output_path) = output {
                profile_data.save_to_file(&output_path)?;
                println!("{}", format!("Profile data saved to: {}", output_path.display()).green());
            }
            
            output_manager.save_result(&profile_data, "performance_profile")?;
            
            println!("{}", "Performance Profile Results".green().bold());
            println!("{}", profile_data);
        }
        
        Commands::Report { target, format, template, output } => {
            progress_bar.set_message("Generating comprehensive report...");
            
            let analyzer = MemoryAnalyzer::new(config.clone());
            let report = analyzer.generate_report(&target, format, template).await?;
            
            progress_bar.finish_with_message("Report generation completed");
            
            if let Some(output_path) = output {
                std::fs::write(&output_path, &report)?;
                println!("{}", format!("Report saved to: {}", output_path.display()).green());
            }
            
            output_manager.save_result(&report, "comprehensive_report")?;
            
            println!("{}", "Comprehensive Report Generated".green().bold());
            println!("Report length: {} characters", report.len());
        }
    }
    
    info!("XILLEN Memory Analyzer completed successfully");
    Ok(())
}
