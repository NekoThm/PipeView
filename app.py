from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

def parse_o3_pipeview_stream(file_storage, start_tick, end_tick):
    """
    流式解析 trace 文件。
    直接迭代 file_storage 对象获取二进制行，避免 TextIOWrapper兼容性问题。
    """
    instructions_map = {}
    current_grouped_inst = None
    
    min_tick_in_range = float('inf')
    tick_margin = 10000 
    
    # 确保从头开始读取
    file_storage.seek(0)

    # 直接迭代 file_storage，它会产生 bytes 类型的行
    for binary_line in file_storage:
        # 手动解码，忽略错误
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

        # --- 1. 处理 Fetch (新指令) ---
        if stage == 'fetch':
            # 核心过滤逻辑
            
            # A. 如果设置了结束时间，且当前 tick 远超结束时间 -> 停止读取
            if end_tick > 0 and tick > end_tick + tick_margin:
                break 
            
            # B. 如果小于开始时间 -> 跳过
            if tick < start_tick:
                continue
            
            # C. 在范围内 -> 解析
            if len(parts) < 6: continue
            try:
                sn = int(parts[5])
                disasm = ":".join(parts[6:])
                inst = {
                    "id": sn,
                    "pc": parts[3],
                    "disasm": disasm,
                    "stages": {"fetch": tick},
                    "is_flushed": False 
                }
                instructions_map[sn] = inst
                current_grouped_inst = inst
                
                if tick < min_tick_in_range:
                    min_tick_in_range = tick
                    
            except (ValueError, IndexError):
                continue

        # --- 2. 处理其他阶段 ---
        else:
            # 只有当该指令已经被收录（即 fetch 在范围内）时，才更新后续阶段
            target_inst = None
            
            # 尝试 Explicit SN 匹配
            if len(parts) > 3:
                try:
                    possible_sn = int(parts[-1])
                    if possible_sn in instructions_map:
                        target_inst = instructions_map[possible_sn]
                except ValueError: pass
            
            # 尝试 Implicit Context 匹配
            if not target_inst and current_grouped_inst:
                target_inst = current_grouped_inst
            
            if target_inst:
                if tick > 0:
                    target_inst["stages"][stage] = tick
                
                if stage == 'retire':
                    if tick == 0:
                        target_inst["is_flushed"] = True
                    if target_inst == current_grouped_inst:
                        current_grouped_inst = None

    # 后处理：转换为列表并排序
    result_list = list(instructions_map.values())
    result_list.sort(key=lambda x: x['id'])
    
    # 再次检查 flush 状态
    for inst in result_list:
        if 'retire' not in inst['stages'] or inst['stages']['retire'] == 0:
            inst['is_flushed'] = True

    # 如果没有找到数据，min_tick 默认为 start_tick，防止前端计算出错
    final_min = min_tick_in_range if result_list else start_tick
    
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
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    # 获取范围参数
    try:
        start_tick = int(request.form.get('start_tick', 0))
    except:
        start_tick = 0
        
    try:
        end_tick = int(request.form.get('end_tick', -1))
    except:
        end_tick = -1 

    try:
        # 直接传入 file 对象，而不是 file.stream
        data = parse_o3_pipeview_stream(file, start_tick, end_tick)
        return jsonify(data)
    except Exception as e:
        import traceback
        traceback.print_exc() # 在控制台打印详细错误，方便调试
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)


