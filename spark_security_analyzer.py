from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_extract, count, when
spark = SparkSession.builder \
    .appName("WebServerLogSecurityAnalyzer") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

input_path = "file:///home/hduser/server_access.log"
raw_logs = spark.read.text(input_path)

# format: IP - - [timestamp] "METHOD URL PROTOCOL" STATUS BYTES
clf_pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
parsed_logs = raw_logs.select(
    regexp_extract(col("value"), clf_pattern, 1).alias("ip"),
    regexp_extract(col("value"), clf_pattern, 2).alias("timestamp"),
    regexp_extract(col("value"), clf_pattern, 3).alias("method"),
    regexp_extract(col("value"), clf_pattern, 4).alias("url"),
    regexp_extract(col("value"), clf_pattern, 5).alias("protocol"),
    regexp_extract(col("value"), clf_pattern, 6).cast("int").alias("status"),
    regexp_extract(col("value"), clf_pattern, 7).cast("int").alias("bytes")
)

security_analyzed = parsed_logs.withColumn(
    "threat_category",
     when(col("url").rlike(r"(?i)(SELECT.*FROM|UNION.*SELECT|OR.*1=1|--)"), "SQL Injection")
     .when(col("url").rlike(r"(?i)(<script>|alert\(|%3Cscript%3E)"), "Cross-Site Scripting (XSS)")
     .when(col("url").rlike(r"(?i)(\.\./|/etc/passwd)"), "Path Traversal")
     .otherwise("Benign Traffic")
)

print("\n" + "="*50)
print("                     SECURITY ANALYSIS REPORT                             ")
print("="*50)
print("\n--- 1. Attack Breakdown By Type ---")
security_analyzed.groupBy("threat_category").count().orderBy(col("count").desc()).show(truncate=False)

print("---2. Top Malicious Attacker IPs ---")
security_analyzed.filter(col("threat_category") != "Benign Traffic") \
     .groupBy("ip", "threat_category") \
     .agg(count("*").alias("attack_attempts")) \
     .orderBy(col("attack_attempts").desc()) \
     .show(10, truncate=False)
print("---3. Total Request Volume by IP (DDoS Detection) ---")
security_analyzed.groupBy("ip") \
     .agg(count("*").alias("total_requests")) \
     .orderBy(col("total_requests").desc()) \
     .show(10, truncate=False)

output_path = "file:///home/hduser/flagged_threats"
security_analyzed.filter(col("threat_category") != "Benign Traffic") \
    .write \
    .mode("overwrite") \
    .parquet(output_path)
# --- ACTIVE MITIGATION CODE SNIPPET ---
print("--- 4. Generating Cybersecurity Mitigation Script ---")
try:
    import os
    target_df = None
    for var_name, var_val in list(locals().items()):
        if hasattr(var_val, "columns") and "ip" in var_val.columns:
            target_df = var_val
            break
            
    if target_df is not None:
        if "threat_category" in target_df.columns:
            malicious_ip_list = [row['ip'] for row in target_df.filter("threat_category != 'Benign Traffic'").select("ip").distinct().collect()]
        else:
            malicious_ip_list = [row['ip'] for row in target_df.select("ip").distinct().collect()]
            
        malicious_ip_list = [ip for ip in malicious_ip_list if ip and str(ip).strip()]
        
        custom_dir = os.path.dirname(output_path.replace("file://", "")) if 'output_path' in locals() else "/home/hduser"
        mitigation_script_path = os.path.join(custom_dir, "block_attackers.sh")
        
        with open(mitigation_script_path, "w") as f:
            f.write("#!/bin/bash\n# Generated automatically by PySpark Analyzer\n\n")
            for ip in malicious_ip_list:
                f.write(f"echo 'Blocking malicious attacker IP: {ip}'\n")
                f.write(f"sudo iptables -A INPUT -s {ip} -j DROP\n")
                
        os.chmod(mitigation_script_path, 0o755)
        print(f"[+] Automated mitigation firewall script generated at: {mitigation_script_path}")
    else:
        print("[-] Failed to generate script: Could not find log data variables.")
except Exception as e:
    print(f"[-] Failed to generate script: {str(e)}")
# ---------------------------------------

print(f"\n[+] Flagged threat logs written to: {output_path}\n")

spark.stop()

