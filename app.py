from flask import Flask, request, jsonify, render_template
import collections

app = Flask(__name__)

def parse_o3_pipeview_stream(file_storage, start_tick, end_tick):
    instructions_map = {}
    current_grouped_inst = None
    
    # 暂存 Cache 事件的缓冲区
    pending_cache_events = collections.defaultdict(list)
    
    min_tick_in_range = float('inf')
    tick_margin = 10000 
    
    file_storage.seek(0)

    for binary_line in file_storage:
        try:
            line = binary_line.decode('utf-8', errors='ignore').strip()
        except:
            continue

        if not line.startswith("O3PipeView:"):
            continue
        
        parts = line.split(':')
        if len(parts) < 3: continue

        stage = parts[1]
        try:
            tick = int(parts[2])
        except ValueError:
            continue

        # --- 1. 处理 Cache Miss ---
        if stage == 'cache':
            if len(parts) >= 9 and parts[6] == 'sn':
                result = parts[8].strip()
                if 'miss' in result.lower():
                    try:
                        sn = int(parts[7])
                        # [修改] 增加 "vaddr": parts[4]
                        event = { 
                            "tick": tick, 
                            "type": parts[3], 
                            "vaddr": parts[4], # 新增：解析虚拟地址
                            "paddr": parts[5], 
                            "result": result 
                        }
                        
                        if sn in instructions_map:
                            if 'cache_events' not in instructions_map[sn]: instructions_map[sn]['cache_events'] = []
                            instructions_map[sn]['cache_events'].append(event)
                        else:
                            pending_cache_events[sn].append(event)
                    except ValueError: pass
            continue

        # --- 2. 处理 Fetch ---
        elif stage == 'fetch':
            if end_tick > 0 and tick > end_tick + tick_margin: break 
            if tick < start_tick: continue
            if len(parts) < 6: continue
            try:
                sn = int(parts[5])
                disasm = ":".join(parts[6:])
                inst = {
                    "id": sn, "pc": parts[3], "disasm": disasm,
                    "stages": {"fetch": tick}, "is_flushed": False, "cache_events": [] 
                }
                if sn in pending_cache_events:
                    inst['cache_events'].extend(pending_cache_events[sn])
                    del pending_cache_events[sn]
                
                instructions_map[sn] = inst
                current_grouped_inst = inst
                if tick < min_tick_in_range: min_tick_in_range = tick
            except: continue

        # --- 3. 处理其他阶段 (含 Store 解析) ---
        else:
            target_inst = None
            if len(parts) > 3:
                try:
                    possible_sn = int(parts[-1])
                    if possible_sn in instructions_map: target_inst = instructions_map[possible_sn]
                except ValueError: pass
            if not target_inst and current_grouped_inst: target_inst = current_grouped_inst
            
            if target_inst:
                if tick > 0:
                    target_inst["stages"][stage] = tick
                
                if stage == 'retire':
                    if tick == 0: target_inst["is_flushed"] = True
                    # 解析 Store
                    if len(parts) >= 5 and parts[3] == 'store':
                        try:
                            store_tick = int(parts[4])
                            if store_tick > 0:
                                target_inst["stages"]["store"] = store_tick
                        except ValueError: pass

                    if target_inst == current_grouped_inst:
                        current_grouped_inst = None

    # 后处理
    result_list = list(instructions_map.values())
    result_list.sort(key=lambda x: x['id'])
    for inst in result_list:
        if 'retire' not in inst['stages'] or inst['stages']['retire'] == 0:
            inst['is_flushed'] = True

    # [修复错误] 明确计算 final_min
    if result_list and min_tick_in_range != float('inf'):
        final_min = min_tick_in_range
    else:
        final_min = start_tick
    
    return {
        "min_tick": final_min, 
        "instructions": result_list,
        "count": len(result_list)
    }

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
        data = parse_o3_pipeview_stream(file, start_tick, end_tick)
        return jsonify(data)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)