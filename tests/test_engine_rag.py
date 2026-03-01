from orchestrator.kernel import orchestrator_engine as engine

# Execute real orchestrator for a very basic target, static mode first to see if it even works
# Wait, let's run dynamic mode, with just whatweb to test the loop
target = "scanme.nmap.org"
generator = engine.run_orchestrator(target, "whatweb", concurrency=4, mode="dynamic", dry_run=True)

for line in generator:
    if isinstance(line, str):
        print(line.strip('\n'))
    else:
        print(f"Object yielded: {type(line)}")

