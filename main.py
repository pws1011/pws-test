def main():
    print("Initializing BTR-SDN Simulation...")
    env = NetworkEnvironment()
    
    # 设置恶意节点 (ID 0 - 5)
    malicious_nodes = list(range(6))
    env.set_malicious_nodes(malicious_nodes)
    print(f"Malicious Nodes: {malicious_nodes} (Will attack during round 10-25)")
    
    # 存储历史数据用于绘图
    history = {'trust': [], 'time': [], 'breaches': []}
    
    print("\nStarting Simulation Loop...")
    print(f"{'Round':<5} | {'Avg Trust':<10} | {'Route Time(ms)':<15} | {'Breaches':<10}")
    print("-" * 50)
    
    for r in range(Config.SIMULATION_ROUNDS):
        stats = env.step(r)
        
        history['trust'].append(stats['avg_trust'])
        history['time'].append(stats['avg_time'])
        history['breaches'].append(stats['breaches'])
        
        if r % 5 == 0:
            print(f"{r:<5} | {stats['avg_trust']:.4f}     | {stats['avg_time']:.4f}          | {stats['breaches']}")

    # ==========================
    # 结果
    # ==========================
    plt.figure(figsize=(12, 4))
    
    # 信任值演变 (展示恢复机制)
    plt.subplot(1, 3, 1)
    plt.plot(history['trust'], label='Net Avg Trust', color='blue', linewidth=2)
    plt.axvspan(10, 25, color='red', alpha=0.1, label='Attack Period')
    plt.axvspan(25, 30, color='green', alpha=0.1, label='Recovery Period') # 理论恢复期
    plt.title('Trust Evolution with Recovery')
    plt.xlabel('Simulation Round')
    plt.ylabel('Trust Score')
    plt.legend()
    plt.grid(True)
    
   print("Simulation started...")
    for r in range(Config.SIMULATION_ROUNDS):
        result = env.step(r)
        simulation_history.append(result)
        if r % 10 == 0:
            print(f"Round {r} completed...")

    # 执行导出
    exporter = ResultExporter()
    exporter.export_to_csv("simulation_results.csv", simulation_history)
    exporter.export_summary_report("final_report.txt", simulation_history, env.malicious_targets)

if __name__ == "__main__":

    main()
