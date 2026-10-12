//! Reproducible controller workloads; these synthetic levels do not activate
//! production R4/R8/R16 and do not replace real MaleCNS calibration.
use flypow_target_protocol::difficulty::*;
fn levels()->Vec<Level>{[2,4,8,16].iter().enumerate().map(|(i,r)|Level{profile_id:format!("synthetic-r{r}"),required_backgrounds:*r,difficulty_micros:1_000_000*(1<<i),calibration_hash:"a".repeat(64),enabled:true}).collect()}
#[test]fn cadence_step_changes_offline_and_adversarial_bounds(){
 let l=levels();let mut c=Controller::new("comparable".into(),&l,300000).unwrap();
 for t in 1..60{c.observe(&l,"comparable",t,Some(300000),true).unwrap();}assert_eq!(c.applied_index,0);
 for t in 60..120{let frozen=c.clone();c.observe(&l,"comparable",t,Some(15000),true).unwrap();assert!(c.applied_index<=frozen.applied_index+1);assert!(c.desired_micros<=frozen.desired_micros*125/100);}
 assert_eq!(c.applied_index,3);let fast=c.clone();for t in 120..140{c.observe(&l,"comparable",t,None,false).unwrap();}assert_eq!(c.desired_micros,fast.desired_micros);assert_eq!(c.valid_samples,fast.valid_samples);
 for t in 140..260{c.observe(&l,"comparable",t,Some(3_000_000),true).unwrap();}assert_eq!(c.applied_index,0);
 for t in 260..320{c.observe(&l,"comparable",t,Some(if t%2==0{1}else{86_400_000}),true).unwrap();assert!((1_000_000..=8_000_000).contains(&c.desired_micros));}
 let persisted=serde_json::to_string(&c).unwrap();let mut restored:Controller=serde_json::from_str(&persisted).unwrap();assert_eq!(restored.desired_micros,c.desired_micros);assert!(restored.observe(&l,"comparable",318,Some(1),true).is_err());restored.observe(&l,"different-family",320,Some(0),true).unwrap();assert_eq!(restored.valid_samples,1);assert_eq!(restored.applied_index,0);
 let only=&l[..1];let mut ceiling=Controller::new("r2".into(),only,300000).unwrap();for t in 1..50{ceiling.observe(only,"r2",t,Some(1),true).unwrap();}assert_eq!(ceiling.applied_index,0);assert_eq!(ceiling.reason,"calibrated-ceiling");
}
