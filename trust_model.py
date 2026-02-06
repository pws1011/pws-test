import networkx as nx
import numpy as np
import random
import time
import math
import matplotlib.pyplot as plt
from collections import deque



# Trust Model with Recovery
# ==========================================
class TrustManager:
    """
    实现 FAHP 评估与信誉恢复机制
    """
    def __init__(self, node_id):
        self.node_id = node_id
        self.trust_score = Config.INIT_TRUST
        self.history_score = Config.INIT_TRUST
        
        # 状态标志
        self.is_isolated = False      # 是否被隔离 (黑名单)
        self.in_probation = False     # 是否在考察期
        self.malicious_ts = 0         # 被标记为恶意的时间戳
        
        # 恢复机制数据结构
        self.recovery_window = deque(maxlen=Config.RECOVERY_WIN_SIZE)

    def calculate_fahp_score(self, metrics):
        """
        模拟 FAHP 多维属性加权计算 (简化矩阵运算)
        Metrics: cpu_load, drop_rate, attack_logs
        """
        # 权重向量 (特征向量)
        w = {'cpu': 0.2, 'drop': 0.5, 'sec': 0.3}
        
        # 归一化评分 (越小越好 -> 分数越高)
        s_cpu = max(0, 1 - metrics['cpu'])
        s_drop = max(0, 1 - metrics['drop'])
        s_sec = 1.0 if metrics['attacks'] == 0 else 0.0
        
        direct_trust = w['cpu']*s_cpu + w['drop']*s_drop + w['sec']*s_sec
        return direct_trust

    def update(self, metrics, current_time):
        """
        周期性更新信任值，包含恢复逻辑 (核心算法实现)
        """
        # 1. 计算本周期直接信任值
        direct_trust = self.calculate_fahp_score(metrics)
        
        # === A. 隔离恢复阶段 (Isolation & Recovery) ===
        if self.is_isolated:
            # 公式 16: 滑动窗口合规积分
            is_compliant = 1 if direct_trust > 0.8 else 0
            self.recovery_window.append(is_compliant)
            
            # 计算恢复积分
            compliance_sum = sum(self.recovery_window)
            
            # 公式 15: 恶意权重时间衰减
            # 随着时间推移，对历史恶意的惩罚权重降低，此处体现为恢复门槛稍微降低
            time_factor = math.exp(-Config.DECAY_LAMBDA * (current_time - self.malicious_ts))
            required_score = Config.RECOVERY_WIN_SIZE * 0.8  # 基础要求: 80% 时间合规
            
            if len(self.recovery_window) == Config.RECOVERY_WIN_SIZE and compliance_sum >= required_score:
                # 触发恢复 -> 进入考察期
                self.is_isolated = False
                self.in_probation = True
                self.trust_score = 0.5  # 重置为中立
                self.recovery_window.clear()
            else:
                self.trust_score = 0.1  # 保持低分
        
        # === B. 正常/考察期阶段 (Normal / Probation) ===
        else:
            # 历史融合 (指数加权移动平均)
            alpha = 0.7
            raw_score = alpha * self.history_score + (1 - alpha) * direct_trust
            
            if self.in_probation:
                # 公式 17: 考察期动态惩罚
                # 如果在考察期表现不好，惩罚因子生效
                if direct_trust < 0.6:
                    print(f"Node {self.node_id} failed probation! Re-isolating.")
                    self.is_isolated = True
                    self.malicious_ts = current_time
                    self.trust_score = 0.2
                else:
                    # 考察期得分会被压制，防止“摆烂攻击”
                    self.trust_score = raw_score - Config.PROBATION_PENALTY * (1 - raw_score)
                    
                    # 检查是否度过考察期 (假设考察期为 3 个周期)
                    if current_time - self.malicious_ts > (Config.RECOVERY_WIN_SIZE + 3):
                        self.in_probation = False
            else:
                self.trust_score = raw_score
                
                # 触发隔离机制
                if self.trust_score < 0.4:
                    self.is_isolated = True
                    self.malicious_ts = current_time
                    self.recovery_window.clear()

        # 更新历史
        self.history_score = self.trust_score
        return self.trust_score
