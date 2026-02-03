import sqlite3
import json
import time
import os
from pathlib import Path

class PersistentLearningDB:
    def __init__(self, db_path="omnistrike_learning.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS attacks
                     (id INTEGER PRIMARY KEY, target TEXT, vector TEXT, payload TEXT, result TEXT, timestamp REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS tools
                     (id INTEGER PRIMARY KEY, purpose TEXT, code TEXT, success_rate REAL, attempts INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS strategies
                     (id INTEGER PRIMARY KEY, target_type TEXT, effective_vectors TEXT)''')
        conn.commit()
        conn.close()

    def log_attack(self, target, vector, payload, result):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT INTO attacks (target, vector, payload, result, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (target, vector, str(payload), result, time.time()))
        conn.commit()
        conn.close()

    def get_effective_payloads(self, vector):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT payload FROM attacks WHERE vector=? AND result='SUCCESS' ORDER BY timestamp DESC", (vector,))
        results = [r[0] for r in c.fetchall()]
        conn.close()
        return results

    def save_ai_tool(self, purpose, code):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT INTO tools (purpose, code, success_rate, attempts) VALUES (?, ?, 0.0, 0)", (purpose, code))
        conn.commit()
        conn.close()

class SelfHealingEngine:
    """
    Handles autonomous recovery and tool generation using AI.
    """
    def __init__(self, ai_engine, db):
        self.ai_engine = ai_engine
        self.db = db

    async def heal_and_retry(self, target, failure_reason, original_vector):
        print(f"[*] Self-healing triggered for {target}. Reason: {failure_reason}")

        prompt = f"""
        Objective: Exploit target {target} via {original_vector}.
        Previous failure: {failure_reason}.
        Task: Generate a new Python exploit script or payload that bypasses this issue.
        Output ONLY the code block.
        """

        # Consult AI Consensus
        consensus = await self.ai_engine.get_consensus(prompt)
        new_code = consensus.get('summary', '# No code generated')

        # Save to DB
        self.db.save_ai_tool(f"{original_vector}_{target}", new_code)

        # Save to generated_tools directory
        tools_dir = Path("generated_tools")
        tools_dir.mkdir(exist_ok=True)
        tool_path = tools_dir / f"tool_{int(time.time())}.py"
        tool_path.write_text(new_code)

        return tool_path
