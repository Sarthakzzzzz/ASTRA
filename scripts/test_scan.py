from orchestrator.kernel.orchestrator_engine import run_orchestrator

print("Starting scan on scanme.nmap.org...")
for log in run_orchestrator('scanme.nmap.org', 'nmap', 2, 'dynamic'):
    print(log, end='')
print("\nScan completed successfully!")
