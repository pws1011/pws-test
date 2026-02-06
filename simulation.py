class NetworkEnvironment:
    def __init__(self):
        # 使用 Barabasi-Albert 模拟 GÉANT 的无标度特性
        self.graph = nx.barabasi_albert_graph(Config.NUM_DOMAINS, 2, seed=42)
        self.ledger = SimulatedLedger()
        self.trust_managers = {n: TrustManager(n) for n in self.graph.nodes}
        
        # 初始化链路属性 (带宽 Mbps, 时延 ms)
        for u, v in self.graph.edges:
            self.graph[u][v]['bw'] = random.randint(100, 1000)
            self.graph[u][v]['delay'] = random.randint(2, 20)

    def set_malicious_nodes(self, target_nodes):
        self.malicious_targets = set(target_nodes)

    def get_node_metrics(self, node_id, round_idx):
        """生成节点行为数据 (模拟攻击行为)"""
        # 模拟 On-Off 攻击: 第 10-25 轮进行攻击，之后装好人
        is_attacker = node_id in self.malicious_targets
        attacking_now = is_attacker and (10 <= round_idx <= 25)
        
        if attacking_now:
            return {'cpu': 0.9, 'drop': 0.6, 'attacks': 1} # 恶意行为
        else:
            return {'cpu': 0.2, 'drop': 0.01, 'attacks': 0} # 正常行为

    def find_trusted_path(self, src, dst):
        """
        BTR-SDN 路由算法: 
        1. 基于信任的剪枝
        2. 综合权重 Dijkstra
        """
        start_t = time.time()
        
        # 构建可信子图 (Pruning)
        trusted_graph = nx.Graph()
        for u, v in self.graph.edges:
            t_u = self.trust_managers[u].trust_score
            t_v = self.trust_managers[v].trust_score
            
            # 剪枝策略: 只有两端都非黑名单，且至少一端是可信核心(>Threshold)才保留链路
            # 这里简化为: 只要不是隔离状态就可以走，但权重受信任值影响
            if not (self.trust_managers[u].is_isolated or self.trust_managers[v].is_isolated):
                # 权重函数: Cost = Delay + (1 / Trust)
                # 信任值越低，Cost 越高，越不容易被选中
                joint_trust = (t_u + t_v) / 2
                weight = self.graph[u][v]['delay'] + (10 / (joint_trust + 0.01))
                trusted_graph.add_edge(u, v, weight=weight)
        
        try:
            path = nx.shortest_path(trusted_graph, src, dst, weight='weight')
            calc_time = (time.time() - start_t) * 1000 # ms
            
            # 记录上链
            self.ledger.commit_route_log(src, dst, path)
            return path, calc_time
        except nx.NetworkXNoPath:
            return None, 0.0

    def step(self, round_idx):
        """执行一轮仿真"""
        # 1. 更新信任
        avg_trust = 0
        for n in self.graph.nodes:
            metrics = self.get_node_metrics(n, round_idx)
            score = self.trust_managers[n].update(metrics, round_idx)
            self.ledger.commit_trust_update(n, score, round_idx)
            avg_trust += score
            
        # 2. 产生随机跨域请求并路由
        route_success = 0
        total_req = 10
        security_breaches = 0
        calc_times = []
        path_lengths = []
        
        for _ in range(total_req):
            s, d = random.sample(list(self.graph.nodes), 2)
            path, c_time = self.find_trusted_path(s, d)
            
            if path:
                route_success += 1
                calc_times.append(c_time)
                path_lengths.append(len(path))
                
                # 安全性检查: 路径中是否包含正在攻击的恶意节点？
                for hop in path:
                    # 如果节点正在攻击 (metrics差) 但仍被选中，算作安全漏洞
                    metrics = self.get_node_metrics(hop, round_idx)
                    if metrics['attacks'] > 0:
                        security_breaches += 1
        
        return {
            'avg_trust': avg_trust / Config.NUM_DOMAINS,
            'success_rate': route_success / total_req,
            'avg_time': np.mean(calc_times) if calc_times else 0,
            'avg_len': np.mean(path_lengths) if path_lengths else 0,
            'breaches': security_breaches
        }
