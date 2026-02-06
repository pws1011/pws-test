"""
BTR-SDN: Blockchain-enabled Trusted Routing Simulation Framework
Author: [pws/Lab]
License: MIT
Description: Simulation of multi-domain SDN trusted routing with reputation recovery mechanism.
"""

import networkx as nx
import numpy as np
import random
import time
import math
import matplotlib.pyplot as plt
from collections import deque


class Config:
    # 实验环境设置
    NUM_DOMAINS = 20          # 对应 GÉANT 拓扑规模
    SIMULATION_ROUNDS = 50    # 仿真轮次
    REPEATS = 10              # 统计重复次数 (符合实验设置描述)
    
    # 信任模型参数
    TRUST_THRESHOLD = 0.7     # 可信节点阈值
    RECOVERY_WIN_SIZE = 5     # 恢复观察窗口大小 (W_win)
    DECAY_LAMBDA = 0.3        # 恶意权重衰减系数 (λ in Eq. 15)
    PROBATION_PENALTY = 0.4   # 考察期惩罚因子 (Eq. 17)
    INIT_TRUST = 0.5          # 初始信任值
    
    # 流量与攻击设置
    TRAFFIC_INTER_RATIO = 0.6 # 跨域流量占比
    ATTACK_RATIO = 0.3        # 恶意节点比例 (30%)
    
    # 区块链参数
    BLOCK_SIZE = 100          # 交易/块
    CONSENSUS_DELAY = 0.05    # 模拟共识延迟 (秒)
