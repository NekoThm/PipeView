from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

def parse_o3_pipeview(content):
    instructions_map = {}
    current_grouped_inst = None
    lines = content.splitlines()

    for line in lines:
        line = line.strip()
        if not line.startswith("O3PipeView:"):
            continue
        
        parts = line.split(':')
        if len(parts) < 3: continue

        stage = parts[1]
        try:
            tick = int(parts[2])
        except ValueError:
            continue

        if stage == 'fetch':
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
            except (ValueError, IndexError):
                continue
        else:
            target_inst = None
            if len(parts) > 3:
                try:
                    possible_sn = int(parts[-1])
                    if possible_sn in instructions_map:
                        target_inst = instructions_map[possible_sn]
                except ValueError: pass
            
            if not target_inst and current_grouped_inst:
                target_inst = current_grouped_inst
            
            if target_inst:
                # 记录该阶段时间
                if tick > 0:
                    target_inst["stages"][stage] = tick
                
                # 如果是 retire 且 tick=0，标记为 flush
                if stage == 'retire':
                    if tick == 0:
                        target_inst["is_flushed"] = True
                    if target_inst == current_grouped_inst:
                        current_grouped_inst = None

    result_list = list(instructions_map.values())
    result_list.sort(key=lambda x: x['id'])
    
    # 二次检查：如果没有 retire 阶段，视为 flushed
    for inst in result_list:
        if 'retire' not in inst['stages'] or inst['stages']['retire'] == 0:
            inst['is_flushed'] = True

    final_min_tick = 0
    if result_list:
        final_min_tick = result_list[0]['stages']['fetch']
    
    return {
        "min_tick": final_min_tick, 
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
    try:
        content = file.read().decode('utf-8', errors='ignore')
        data = parse_o3_pipeview(content)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
