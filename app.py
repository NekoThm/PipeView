from flask import Flask, request, jsonify, render_template
import collections

app = Flask(__name__)

# --- O3CPU Parser (保持不变) ---
def parse_o3_pipeview_stream(file_storage, start_tick, end_tick):
    instructions_map = {}
    current_grouped_inst = None
    pending_cache_events = collections.defaultdict(list)
    min_tick_in_range = float('inf')
    tick_margin = 10000 
    
    # O3 逻辑较为复杂，暂时维持原样，仅做简单的范围判定
    parse_start = max(0, start_tick - tick_margin)

    file_storage.seek(0)
    for binary_line in file_storage:
        try:
            line = binary_line.decode('utf-8', errors='ignore').strip()
        except: continue
        if not line.startswith("O3PipeView:"): continue
        parts = line.split(':')
        if len(parts) < 3: continue
        stage = parts[1]
        try: tick = int(parts[2])
        except: continue

        if stage == 'cache':
            # ... (Cache逻辑保持不变)
            if len(parts) >= 9 and parts[6] == 'sn':
                result = parts[8].strip()
                if 'miss' in result.lower():
                    try:
                        sn = int(parts[7])
                        event = { "tick": tick, "type": parts[3], "vaddr": parts[4], "paddr": parts[5], "result": result }
                        if sn in instructions_map:
                            if 'cache_events' not in instructions_map[sn]: instructions_map[sn]['cache_events'] = []
                            instructions_map[sn]['cache_events'].append(event)
                        else: pending_cache_events[sn].append(event)
                    except: pass
            continue
        elif stage == 'fetch':
            if end_tick > 0 and tick > end_tick + tick_margin: break 
            if tick < parse_start: continue # 使用回溯后的起点
            if len(parts) < 6: continue
            try:
                sn = int(parts[5])
                disasm = ":".join(parts[6:])
                inst = { "id": sn, "pc": parts[3], "disasm": disasm, "stages": {"fetch": tick}, "is_flushed": False, "cache_events": [] }
                if sn in pending_cache_events:
                    inst['cache_events'].extend(pending_cache_events[sn])
                    del pending_cache_events[sn]
                instructions_map[sn] = inst
                current_grouped_inst = inst
                if tick < min_tick_in_range: min_tick_in_range = tick
            except: continue
        else:
            target_inst = None
            if len(parts) > 3:
                try:
                    possible_sn = int(parts[-1])
                    if possible_sn in instructions_map: target_inst = instructions_map[possible_sn]
                except: pass
            if not target_inst and current_grouped_inst: target_inst = current_grouped_inst
            
            if target_inst:
                if tick > 0: target_inst["stages"][stage] = tick
                if stage == 'retire':
                    if tick == 0: target_inst["is_flushed"] = True
                    if len(parts) >= 5 and parts[3] == 'store':
                        try:
                            store_tick = int(parts[4])
                            if store_tick > 0: target_inst["stages"]["store"] = store_tick
                        except: pass
                    if target_inst == current_grouped_inst: current_grouped_inst = None

    # 过滤：移除那些在 start_tick 之前就完全结束的指令
    final_list = []
    for inst in instructions_map.values():
        if 'retire' not in inst['stages'] or inst['stages']['retire'] == 0: inst['is_flushed'] = True
        
        # 计算指令结束时间 (Retire > Complete > ... > Fetch)
        end_time = 0
        for s in inst['stages'].values():
            if s > end_time: end_time = s
        
        # 只要指令结束时间晚于用户的 start_tick，就保留
        if end_time >= start_tick:
            final_list.append(inst)

    final_list.sort(key=lambda x: x['id'])
    
    # 这里的 min_tick 还是尽量反映真实数据的起点
    if final_list:
        t_vals = [i['stages'].get('fetch', float('inf')) for i in final_list]
        final_min = min(t_vals) if t_vals else start_tick
    else:
        final_min = start_tick

    return { "min_tick": final_min, "instructions": final_list, "count": len(final_list) }


# --- FlexCPU Parser (优化版) ---
def parse_flex_pipeview_stream(file_storage, user_start_tick, user_end_tick):
    inst_map = {}
    fetch_queue = collections.deque() 
    last_if_pc = None
    
    # [关键变更] 设置回溯窗口 (Lookback Margin)
    # 即使 file 从 0 开始，如果用户只要 100000 之后的数据，我们也从 50000 开始解析
    # 以便捕获那些跨越 100000 边界的指令的 IF/ID 阶段
    LOOKBACK_MARGIN = 50000
    parse_start_tick = max(0, user_start_tick - LOOKBACK_MARGIN)
    
    file_storage.seek(0)
    for binary_line in file_storage:
        try:
            line = binary_line.decode('utf-8', errors='ignore').strip()
        except: continue
        
        if not line.startswith("PIPE_TRACE"): continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 7: continue
        
        try: tick = int(parts[1])
        except: continue
        
        # 结束条件：超过用户终点 + Margin (防止过早截断正在执行的指令)
        if user_end_tick > 0 and tick > user_end_tick + 1000: break
        
        # 开始条件：使用回溯后的时间点
        if tick < parse_start_tick: continue
        
        stage = parts[2]
        try: pc_val = int(parts[4], 16)
        except: pc_val = 0

        # --- Stage Logic (与之前相同) ---
        if stage == 'IF':
            if pc_val != 0:
                if pc_val != last_if_pc:
                    fetch_queue.append({'tick': tick, 'pc': pc_val})
                    last_if_pc = pc_val
            else:
                last_if_pc = 0 

        elif stage == 'ID':
            try: sn = int(parts[3])
            except: sn = 0
            if sn != 0:
                if sn not in inst_map:
                    inst = {
                        "id": sn, "pc": parts[4], "disasm": parts[5].strip('"'),
                        "stages": { "decode": tick },
                        "is_flushed": False, "cache_events": []
                    }
                    inst_map[sn] = inst
                    match_idx = -1
                    for i, f in enumerate(fetch_queue):
                        if f['pc'] == pc_val:
                            match_idx = i
                            break
                    if match_idx != -1:
                        inst['stages']['fetch'] = fetch_queue[match_idx]['tick']
                        for _ in range(match_idx + 1): fetch_queue.popleft()
                    else:
                        inst['stages']['fetch'] = tick

        elif stage == 'EX':
            try: sn = int(parts[3])
            except: sn = 0
            if sn != 0:
                # 孤儿指令修复（针对文件物理截断的情况）
                if sn not in inst_map:
                    inst = {
                        "id": sn, "pc": parts[4], "disasm": parts[5].strip('"'),
                        "stages": { "fetch": tick, "decode": tick, "execute": tick },
                        "is_flushed": False, "cache_events": []
                    }
                    inst_map[sn] = inst
                
                inst = inst_map[sn]
                if 'execute' not in inst['stages']: inst['stages']['execute'] = tick
                inst['stages']['retire'] = tick + 1

    # --- [关键变更] 活跃度过滤 (Liveness Filter) ---
    # 我们解析了 (user_start - margin) 到 user_end 的数据
    # 现在要剔除那些在 user_start 之前就已经死掉的指令
    
    final_list = []
    
    # 将字典转为列表并按ID排序
    raw_list = list(inst_map.values())
    raw_list.sort(key=lambda x: x['id'])

    for inst in raw_list:
        # 找出该指令最晚的一个阶段的时间
        max_stage_tick = 0
        if inst['stages']:
            max_stage_tick = max(inst['stages'].values())
        
        # 规则：只有当指令的结束时间 >= 用户的起始时间，它在当前视窗才是“可见”或“刚结束”的
        # 这样可以保留那种：Fetch在视窗外，但Execute在视窗内的指令
        if max_stage_tick >= user_start_tick:
            final_list.append(inst)

    # 计算前端绘图用的 min_tick
    # 我们希望保持指令的相对时间，所以如果一个指令 Fetch 在 90000，用户看 100000，
    # 我们还是保留 90000 这个数据，前端会把它画在屏幕左侧外面，这是正确的行为。
    final_min = user_start_tick
    if final_list:
        # 找出这些指令中最早的 Fetch 时间 (可能早于 user_start_tick)
        all_fetch_ticks = [i['stages'].get('fetch', float('inf')) for i in final_list]
        if all_fetch_ticks:
            actual_min = min(all_fetch_ticks)
            final_min = actual_min

    return { "min_tick": final_min, "instructions": final_list, "count": len(final_list) }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    try:
        start_tick = int(request.form.get('start_tick', 0))
        end_tick = int(request.form.get('end_tick', -1))
        
        file.seek(0)
        is_flex = False
        for _ in range(50):
            line = file.readline().decode('utf-8', errors='ignore')
            if line.startswith("PIPE_TRACE"):
                is_flex = True
                break
        
        file.seek(0)
        if is_flex:
            data = parse_flex_pipeview_stream(file, start_tick, end_tick)
        else:
            data = parse_o3_pipeview_stream(file, start_tick, end_tick)
            
        return jsonify(data)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)