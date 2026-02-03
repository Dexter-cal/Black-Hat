from omnistrike.plugins.base import BasePlugin

class ConsensusStrategyPlugin(BasePlugin):
    @property
    def name(self):
        return "ConsensusIntelligence"

    @property
    def description(self):
        return "Queries multiple AI models simultaneously to determine the highest-probability attack vector."

    async def run(self, target, data):
        print("[*] Engaging ConsensusIntelligence multi-model analysis...")

        prompt = f"Develop a comprehensive, stealthy infiltration and lateral movement strategy for the target: {target}"

        consensus_data = await self.ai_engine.get_consensus(prompt)

        data['ai_consensus'] = consensus_data
        print(f"[!!!] AI CONSENSUS REACHED: {consensus_data['summary'][:100]}...")
