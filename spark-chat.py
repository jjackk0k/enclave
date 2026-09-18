#!/usr/bin/env python3
"""Spark Chat - terminal chat client for a local model server (Ollama / vLLM / llama.cpp OpenAI-compatible).
Usage: python spark-chat.py [host] [--port N] [--model NAME] [--ollama]
Defaults: host=192.168.1.x prompt, port auto (11434 ollama / 8000 vllm), streams responses.
"""
import sys, json, urllib.request

def post_stream(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=600)

def main():
    args = sys.argv[1:]
    host = args[0] if args and not args[0].startswith("--") else None
    if not host:
        host = input("Spark IP/hostname: ").strip()
    ollama = "--ollama" in args
    port = 11434 if ollama else 8000
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    model = None
    if "--model" in args:
        model = args[args.index("--model") + 1]

    # Auto-detect model if not given
    if not model:
        try:
            if ollama:
                d = json.load(urllib.request.urlopen(f"http://{host}:{port}/api/tags", timeout=10))
                names = [m["name"] for m in d.get("models", [])]
            else:
                d = json.load(urllib.request.urlopen(f"http://{host}:{port}/v1/models", timeout=10))
                names = [m["id"] for m in d.get("data", [])]
                if not names:  # llama.cpp ollama-style listing
                    names = [m["name"] for m in d.get("models", [])]
            if not names:
                sys.exit("No models on that server. Load one first.")
            model = names[0] if len(names) == 1 else None
            if not model:
                print("Models available:")
                for i, n in enumerate(names): print(f"  [{i}] {n}")
                model = names[int(input("Pick a number: ").strip())]
        except Exception as e:
            sys.exit(f"Can't reach a model server at {host}:{port} — {e}")

    print(f"\nSpark Chat — {model} @ {host}:{port} ({'ollama' if ollama else 'openai-compatible'})")
    print("Type your message. 'exit' quits, 'clear' resets context.\n")
    history = []
    while True:
        try:
            msg = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not msg: continue
        if msg.lower() in ("exit", "quit"): break
        if msg.lower() == "clear": history.clear(); print("[context cleared]"); continue
        history.append({"role": "user", "content": msg})
        try:
            if ollama:
                r = post_stream(f"http://{host}:{port}/api/chat",
                                {"model": model, "messages": history, "stream": True})
                print("spark> ", end="", flush=True)
                full = ""
                for line in r:
                    d = json.loads(line)
                    chunk = d.get("message", {}).get("content", "")
                    full += chunk; print(chunk, end="", flush=True)
                    if d.get("done"): break
            else:
                r = post_stream(f"http://{host}:{port}/v1/chat/completions",
                                {"model": model, "messages": history, "stream": True})
                print("spark> ", end="", flush=True)
                full = ""
                for line in r:
                    line = line.decode(errors="replace").strip()
                    if not line.startswith("data:"): continue
                    if line == "data: [DONE]": break
                    chunk = json.loads(line[5:])["choices"][0]["delta"].get("content", "")
                    full += chunk; print(chunk, end="", flush=True)
            print("\n")
            history.append({"role": "assistant", "content": full})
        except Exception as e:
            print(f"[error: {e}]")

if __name__ == "__main__":
    main()
