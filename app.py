from flask import Flask, request, jsonify, render_template
import collections

app = Flask(__name__)

# --- O3CPU Parser (保持不变) ---
def parse_o3_pipeview_stream(file_storage, start_tick, end_tick):
    # ... (原有逻辑保持不变) ...
    instructions_map = {}
    current_grouped_inst = None
    pending_cache_events = collections.defaultdict(list)
    min_tick_in_range = float('inf')
    tick_margin = 10000 
    
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
            if tick < parse_start: continue 
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

    final_list = []
    for inst in instructions_map.values():
        if 'retire' not in inst['stages'] or inst['stages']['retire'] == 0: inst['is_flushed'] = True
        end_time = 0
        for s in inst['stages'].values():
            if s > end_time: end_time = s
        if end_time >= start_tick:
            final_list.append(inst)

    final_list.sort(key=lambda x: x['id'])
    
    if final_list:
        t_vals = [i['stages'].get('fetch', float('inf')) for i in final_list]
        final_min = min(t_vals) if t_vals else start_tick
    else:
        final_min = start_tick

    return { "min_tick": final_min, "instructions": final_list, "count": len(final_list) }

# --- FlexCPU Parser (保持不变) ---
def parse_flex_pipeview_stream(file_storage, user_start_tick, user_end_tick):
    inst_map = {}
    fetch_queue = collections.deque() 
    last_if_pc = None
    last_id_sn = None
    last_ex_sn = None
    
    LOOKBACK_MARGIN = 50000
    parse_start_tick = max(0, user_start_tick - LOOKBACK_MARGIN)
    
    file_storage.seek(0)
    for binary_line in file_storage:
        try:
            line = binary_line.decode('utf-8', errors='ignore').strip()
        except: continue
        
        if not line.startswith("PIPE_TRACE"): continue
        parts = [p.strip() for p in line.split(';')]
        if len(parts) < 7: continue # 必须包含 Status 列
        
        try: tick = int(parts[1])
        except: continue
        
        if user_end_tick > 0 and tick > user_end_tick + 1000: break
        if tick < parse_start_tick: continue
        
        stage_key = parts[2]   # IF, ID, EX
        sn = int(parts[3]) if parts[3].isdigit() else 0
        pc_hex = parts[4]
        try: pc_val = int(pc_hex, 16)
        except: pc_val = 0
        disasm = parts[5].strip('"')
        status = parts[6]      # FETCHED, STALLED, WAITING_MEM, etc.

        if stage_key == 'IF':
            if pc_val != 0:
                if pc_val == last_if_pc and fetch_queue:
                    fetch_queue[-1]['states'].append({'tick': tick, 'status': status})
                else:
                    # 新的 Fetch 序列
                    fetch_queue.append({'pc': pc_val, 'states': [{'tick': tick, 'status': status}]})
                    last_if_pc = pc_val
            else:
                last_if_pc = 0
                if status == 'STALLED' and fetch_queue:
                    fetch_queue[-1]['states'].append({'tick': tick, 'status': status})

        elif stage_key == 'ID':
            if sn != 0:
                last_id_sn = sn
                if sn not in inst_map:
                    inst = {
                        "id": sn, "pc": pc_hex, "disasm": disasm,
                        "stages": { "fetch": [],
                                    "decode": [{"tick": tick, "status": status}],
                                    "execute": [] },
                    }
                    inst_map[sn] = inst
                    # 尝试从 fetch_queue 找对应的 IF 阶段
                    match_idx = -1
                    for i, f in enumerate(fetch_queue):
                        if f['pc'] == pc_val:
                            match_idx = i
                            break
                    if match_idx != -1:
                        f_data = fetch_queue[match_idx]
                        inst['stages']['fetch'] = f_data['states']
                        for _ in range(match_idx + 1): fetch_queue.popleft()
                    else:
                        inst['stages']['fetch'] = [{"tick": tick, "status": "UNKNOWN_IF"}]
                else:
                    inst_map[sn]['stages']['decode'].append({"tick": tick, "status": status})
            else:
                # 修复：处理 sn=0 的情况
                if status == 'STALLED' and last_id_sn is not None and last_id_sn in inst_map:
                    # 将 STALLED 状态追加到上一条指令的 decode 阶段
                    inst_map[last_id_sn]['stages']['decode'].append({"tick": tick, "status": status})
                elif status == 'BUBBLE':
                    # 气泡意味着阶段清空，没有指令驻留
                    last_id_sn = None

        elif stage_key == 'EX':
            if sn != 0:
                last_ex_sn = sn
                if sn not in inst_map:
                    # 容错：如果 ID 没抓到
                    inst_map[sn] = {
                        "id": sn, "pc": pc_hex, "disasm": disasm,
                        "stages": { "fetch": [{"tick": tick, "status": "FIXED"}], 
                                    "decode": [{"tick": tick, "status": "FIXED"}],
                                    "execute": [] },
                    }
                
                inst = inst_map[sn]
                inst['stages']['execute'].append({"tick": tick, "status": status})
            else:
                # 修复：处理 sn=0 的情况
                if status == 'STALLED' and last_ex_sn is not None and last_ex_sn in inst_map:
                    inst_map[last_ex_sn]['stages']['execute'].append({"tick": tick, "status": status})
                    # 如果 EX 停顿，retire 时间也顺延
                    inst_map[last_ex_sn]['stages']['retire'] = [{"tick": tick, "status": "RETIRE"}]
                elif status == 'BUBBLE':
                    last_ex_sn = None
                

    # 过滤并排序
    raw_list = list(inst_map.values())
    raw_list.sort(key=lambda x: x['id'])
    final_list = []
    for inst in raw_list:
        max_stage_tick = 0
        for s_val in inst['stages'].values():
            if isinstance(s_val, list) and s_val:
                 max_stage_tick = max(max_stage_tick, s_val[-1]['tick'])
        if max_stage_tick >= user_start_tick:
            final_list.append(inst)

    final_min = user_start_tick
    if final_list:
        all_fetch = []
        for i in final_list:
             if 'fetch' in i['stages'] and i['stages']['fetch']:
                 all_fetch.append(i['stages']['fetch'][0]['tick'])
        if all_fetch: final_min = min(all_fetch)

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
            # 增加类型标记
            data['cpu_type'] = 'Flex'
        else:
            data = parse_o3_pipeview_stream(file, start_tick, end_tick)
            # 增加类型标记
            data['cpu_type'] = 'O3'
            
        return jsonify(data)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)