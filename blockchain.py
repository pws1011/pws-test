mport networkx as nx
import numpy as np
import random
import time
import math
import matplotlib.pyplot as plt
from collections import deque

class SimulatedLedger:
    """
    模拟 Hyperledger Fabric 的状态数据库与交易日志
    """
    def __init__(self):
        self.world_state = {}  # 存储 {node_id: trust_score}
        self.transaction_log = []
        self.block_buffer = []

    def commit_trust_update(self, node_id, new_score, timestamp):
        """上链信任更新"""
        tx = {'type': 'TRUST_UPDATE', 'id': node_id, 'val': new_score, 'ts': timestamp}
        self.block_buffer.append(tx)
        self.world_state[node_id] = new_score
        self._try_mint_block()

    def commit_route_log(self, src, dst, path):
        """上链路由路径"""
        tx = {'type': 'ROUTE_LOG', 'src': src, 'dst': dst, 'path': path}
        self.block_buffer.append(tx)
        self._try_mint_block()
        time.sleep(Config.CONSENSUS_DELAY) # 模拟共识耗时

    def _try_mint_block(self):
        if len(self.block_buffer) >= Config.BLOCK_SIZE:
            self.transaction_log.append(self.block_buffer[:])
            self.block_buffer = []
