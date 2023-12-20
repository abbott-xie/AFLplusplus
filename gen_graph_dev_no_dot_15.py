#python ./gen_graph_dev_refactor.py LLVM_IR_FILE CFG_OUT_DIR BINARY_PATH META_FILE
#
import hashlib
import sys
import glob
import sys
import subprocess
from collections import defaultdict
import re

dummy_id_2_local_table = {}
covered_node = []
node_2_callee, func_name_2_root_exit_dict = {}, {}
id_map = {}
global_reverse_graph = defaultdict(list)
global_graph = defaultdict(list)
global_graph_weighted = defaultdict(dict)
global_back_edge = list()
debug_sw = set()
strcmp_node = []
sw_node = []
int_cmp_node = []
eq_cmp_node = []

select_edge_2_cmp_type = {}
sw_border_edge_2_br_dist = {}
missing_cnt = [0]
id_2_fun = {}

ordered_key = []
id_2_cmp_type = {} # connect dummy log_br id to compare type

# Holds the mapping of sancov id of handled branch nodes from the branch sancov
# ID's to their corresponding children sancov ID's. This information is used to
# infer which branches were hit or flipped.
sancov_mapping = defaultdict(list)
sancov_br_list = [] # Holds the (sancov ID's, branch type, br_dist_id)  for handled branches

inline_table= {}
cmp_typ_dic = {'NA': 0, 'ugt': 1, 'sgt': 2, 'eq': 3, 'uge': 4, 'sge': 5, 'ult': 6, 'slt': 7, 'ne': 8, 'ule': 9, 'sle': 10, 'strcmp': 11,  'strncmp':12, 'memcmp':13, 'strstr':14, 'switch': 15}
cond_typ_dic = {'and': 0, 'or': 1, 'xor': 2}
binary_log_funcs = ['log_br8', 'log_br16', 'log_br32', 'log_br64','log_br8_unsign', 'log_br16_unsign', 'log_br32_unsign', 'log_br64_unsign', 'eq_log_br8', 'eq_log_br16', 'eq_log_br32', 'eq_log_br64']
switch_log_funcs = ['sw_log_br8', 'sw_log_br16', 'sw_log_br32', 'sw_log_br64','sw_log_br8_unsign', 'sw_log_br16_unsign', 'sw_log_br32_unsign', 'sw_log_br64_unsign']
strcmp_log_funcs = ['strcmp_log']
strncmp_log_funcs = ['strncmp_log']
memcmp_log_funcs = ['memcmp_log']
strstr_log_funcs = ['strstr_log']
sancov_set = set()
sancov_2_func = {}
func_2_sancov = {}
nm_ret = subprocess.check_output('llvm-nm ' + sys.argv[2], shell=True, encoding='utf-8').splitlines()
internal_func_list = set()
for ele in nm_ret:
    fun_name = ele.split()[-1]
    if len(fun_name) > 200:
        fun_name = fun_name[:20] + hashlib.md5(fun_name.encode()).hexdigest() + fun_name[-20:]
    internal_func_list.add(fun_name)

# ir file + bin file
def inline_counter_table_init(filename, bin_name):
    output = subprocess.check_output('grep "section \\\"__sancov_guards\\\"" ' + filename, shell=True, encoding='utf-8')[:-1]
    lines = [line for line in output.split('\n')]
    ans = {}
    for line in lines:
        data = [ele for ele in line.split(',') if '@__sancov_gen_' in ele][0]
        if data.split()[0] in sancov_set:
            ans[data.split()[0]] = int(data.split()[4][1:])
            ordered_key.append(data.split()[0])

    tmp_sum = 0
    for key in ordered_key:
        inline_table[key] = tmp_sum
#        print(sancov_2_func[key], tmp_sum)
        tmp_sum += ans[key]

    tokens = subprocess.check_output('llvm-nm ' + bin_name + ' |grep sancov_guards', shell=True, encoding='utf-8').split()
    if tmp_sum != ((int('0x'+ tokens[3], 0) - int('0x' + tokens[0], 0))/4):
        print("BUGG: inline table wrong, try to fix...")

    return inline_table


# get sancov id from function
def get_sancov_id_from_function(func):
    lines = func.split("\n")
    func_name = lines[1].split("@")[1].split("(")[0]
    for line in lines:
        if " @__sancov_gen_" in line:
            for subinst in line.split():
                if "__sancov_gen_" in subinst:
                    if "," not in subinst:
                        sancov_set.add(subinst)
                        sancov_2_func[subinst] = func_name
                        func_2_sancov[func_name] = subinst
                    elif subinst.endswith(","):
                        sancov_set.add(subinst[:-1])
                        sancov_2_func[subinst[:-1]] = func_name
                        func_2_sancov[func_name] = subinst[:-1]
                    return
    

# build sancov set from ll file
def build_sancov_set_from_ll_file(ll_file):
    file_content = open(ll_file, 'r').read()
    funcs = file_content.split('; Function Attrs:')
    # begin from the second element of funcs
    for func in funcs[1:]:
        get_sancov_id_from_function(func)

def construct_graph_init_from_func(func_str, inline_table):
    if " @__sancov_gen_" not in func_str:
        return
    graph, reverse_graph = {}, {}
    dot_id_2_llvm_id = {}
    non_sancov_nodes = []
    total_node = 0
    local_table = None
    
    fun_name = func_str.split("\n")[1].split("@")[1].split("(")[0]
    func_str = '\n'.join(func_str.split("\n")[2:])
    # %84 = extractvalue { ptr, i32 } %75, 0, !dbg !227022
    # %75 = landingpad { ptr, i32 }
    func_str = '}'.join(func_str.split("}")[:-1])
    blocks = func_str.split("\n\n")
    for block in blocks:
        # parse node
        dot_node_id = fun_name + "_" + block.split(":")[0]
        code = ':'.join(block.split(":")[1:])
        loc = code.find(' @__sancov_gen_')
        # convert dot node id to llvm node id
        if loc != -1:
            insts = code.split('\n')
            found_the_first_node = 0
            found_the_second_node = 0
            first_node = None
            second_node = None
            found_select = None
            non_first_second_node_select = None
            for inst in insts:
                if "__sancov_gen_" in inst:
                    if "load" in inst and "inttoptr" not in inst:
                        found_the_first_node = 1
                        first_node = inst
                    elif ' = select' not in inst:
                        found_the_second_node = 1
                        second_node = inst
                    else:
                        found_select = 1

            local_edge = None
            # three cases for first/second node checking:
            # 1. bb with first_node
            # 2. bb with second_node
            # 3. bb without first_node and second_node
            if found_the_first_node:
                if not local_table:
                    local_table = first_node.split()[5][:-1]
                local_edge = 0
            elif found_the_second_node:
                if not local_table:
                    local_table = second_node.split()[11]
                local_edge = second_node.split()[15][:-1]
            else:
                non_first_second_node_select = 1
                

            if found_the_first_node or found_the_second_node:
                global_edge = int(int(local_edge)/4) + inline_table[local_table] # "global edge" is the final sancov node id used in AFL++ to trace edge coverage
                dot_id_2_llvm_id[dot_node_id] = global_edge # dot_node_id is the node ID in the raw dot graph

            if found_select:
                if non_first_second_node_select:
                    non_sancov_nodes.append(dot_node_id)
        # handle inject log function
        # map dummy id to local table
        else:
            non_sancov_nodes.append(dot_node_id)
            insts = code.split('\n')

            for _, inst in enumerate(insts):
                if ('call ' in inst or 'invoke ' in inst) and '@' in inst:
                    caller_func_name = inst[inst.find('@')+1:inst.find('(')]
                    # normal cmp condition (log_br)
                    if caller_func_name in (switch_log_funcs + binary_log_funcs + memcmp_log_funcs + strcmp_log_funcs + strncmp_log_funcs + strstr_log_funcs):
                        dummy_id = int(inst.split()[3][:-1])
                        if not local_table:
                            print("BUG: parse local table error!")
                        else:
                            dummy_id_2_local_table[dummy_id] = local_table


        graph[dot_node_id] = []
        if dot_node_id not in reverse_graph:
            reverse_graph[dot_node_id] = []     
    
    for block in blocks:
        # construct a graph with dot node id
        dot_node_id = fun_name + "_" + block.split(":")[0]
        code = ':'.join(block.split(":")[1:])
        insts = code.split('\n')
        for inst_ind, inst in enumerate(insts):
            if re.match(r'\s*br ', inst):
                src_node = dot_node_id
                loc_strt = 0
                while loc_strt >= 0:
                    loc_strt = inst.find("label %", loc_strt)
                    if loc_strt < 0:
                            break
                    loc_end = inst.find(",", loc_strt)
                    
                    if loc_end < 0:
                        dst_node = fun_name + "_" + inst[loc_strt+7:]
                    else:
                        dst_node = fun_name + "_" + inst[loc_strt+7:loc_end]
                    loc_strt = loc_end
                    
                    if dst_node not in graph[src_node]:
                        graph[src_node].append(dst_node)
                    if dst_node not in reverse_graph:
                        reverse_graph[dst_node] = [src_node]
                    else:
                        if src_node not in reverse_graph[dst_node]:
                            reverse_graph[dst_node].append(src_node)
                            
            if re.match(r'\s*switch ', inst):
                src_node = dot_node_id
                select_labels = 0
                while True:
                    select_inst = insts[inst_ind + select_labels]
                    if re.match(r'\s*]', select_inst):
                        break
                    loc_strt = select_inst.find("label %", 0)
                    loc_end = select_inst.find(" ", loc_strt+7)
                    dst_node = fun_name + "_" + select_inst[loc_strt+7:]
                    if loc_end != -1:
                        dst_node = fun_name + "_" + select_inst[loc_strt+7:loc_end]
                    select_labels += 1

                    if dst_node not in graph[src_node]:
                        graph[src_node].append(dst_node)
                    if dst_node not in reverse_graph:
                        reverse_graph[dst_node] = [src_node]
                    else:
                        if src_node not in reverse_graph[dst_node]:
                            reverse_graph[dst_node].append(src_node)
            
            # first situation:
            # %call = invoke noundef nonnull align 8 dereferenceable(56) ptr @_ZN6google8protobuf8internal10LogMessagelsEPKc(ptr noundef nonnull align 8 dereferenceable(56) %12, ptr noundef nonnull @.str. 10)
            # to label %invoke.cont unwind label %lpad, !dbg !226885
            # second situation:
            # invoke void %77(ptr noundef nonnull align 8 dereferenceable(8) %60, i32 noundef %sub)
            # third situation:
            # normal invoke: invoke void @_ZN6google8protobuf8internal10LogMessagelsEPKc(ptr noundef nonnull align 8 dereferenceable(56) %12, ptr noundef nonnull @.str)
            # direct find the label  
            if re.match(r'\s*to\s+label\s+%[^ ]+\s+unwind\s+label\s+%[^ ]+', inst):
                src_node = dot_node_id
                loc_strt = 0
                select_inst = inst
                # first label
                loc_strt = select_inst.find("label %", loc_strt)
                loc_end = select_inst.find(" ", loc_strt + 7)
                dst_node = fun_name + "_" + select_inst[loc_strt+7:loc_end]
                if dst_node not in graph[src_node]:
                    graph[src_node].append(dst_node)
                if dst_node not in reverse_graph:
                    reverse_graph[dst_node] = [src_node]
                else:
                    if src_node not in reverse_graph[dst_node]:
                        reverse_graph[dst_node].append(src_node)
                # second label
                loc_strt = select_inst.find("label %", loc_end)
                loc_end = select_inst.find(",", loc_strt + 7)
                dst_node = fun_name + "_" + select_inst[loc_strt+7:loc_end]
                if dst_node not in graph[src_node]:
                    graph[src_node].append(dst_node)
                if dst_node not in reverse_graph:
                    reverse_graph[dst_node] = [src_node]
                else:
                    if src_node not in reverse_graph[dst_node]:
                        reverse_graph[dst_node].append(src_node)
                
                        
                        
    # TODO: group sancov node (delete ASAN-nodes as well) DONE
    for node in non_sancov_nodes:
        children, parents = graph[node], reverse_graph[node]
        for child in children:
            for parent in parents:
                #if child == -1 or parent == -1:
                #    continue
                if child not in graph[parent]:
                    graph[parent].append(child)
                if parent not in reverse_graph[child]:
                    reverse_graph[child].append(parent)

        del graph[node]
        del reverse_graph[node]
        for parent in parents:
            if parent in graph:
                if node in graph[parent]:
                    graph[parent].remove(node)
        for child in children:
            if child in reverse_graph:
                if node in reverse_graph[child]:
                    reverse_graph[child].remove(node)

    new_graph, new_reverse_graph = {}, {}
    for node, neis in graph.items():
        if dot_id_2_llvm_id[node] not in new_graph:
            new_graph[dot_id_2_llvm_id[node]] = []
        for nei in neis:
            new_graph[dot_id_2_llvm_id[node]].append(dot_id_2_llvm_id[nei])

    for node, neis in reverse_graph.items():
        if dot_id_2_llvm_id[node] not in new_reverse_graph:
            new_reverse_graph[dot_id_2_llvm_id[node]] = []
        for nei in neis:
            new_reverse_graph[dot_id_2_llvm_id[node]].append(dot_id_2_llvm_id[nei])

    # convert node id from dot_id to llvm_instrumented_id, add to global graph
    for node, neis in new_graph.items():
        if not neis:
            global_graph[node] = []
            global_graph_weighted[node] = {}
        for nei in neis:
            global_graph[node].append(nei)
            global_graph_weighted[node][nei] = 1

    for node, neis in reverse_graph.items():
        if not neis:
            global_reverse_graph[node] = []
        for nei in neis:
            global_reverse_graph[node].append(nei)

    if total_node != len(new_graph):
        missing_cnt[0] += 1
    return
    
    
def construct_graph_init_from_ll_file(ll_file, inline_table):
    file_content = open(ll_file, 'r').read()
    funcs = file_content.split('; Function Attrs:')
    for func in funcs[1:]:
        construct_graph_init_from_func(func, inline_table)

# only for normal sancov instrument
# for example:
# getelementptr inbounds ([12 x i32], [12 x i32]* @__sancov_gen_.5, i32 0, i32 0)
# inttoptr (i64 add (i64 ptrtoint ([12 x i32]* @__sancov_gen_.5 to i64), i64 20) to i32*)
def parse_local_edge_from_normal_sancov_instrument(instrument):
    if "inttoptr" not in instrument:
        local_edge = 0
    else:
        local_edge = instrument.split()[15][:-1]
    return local_edge

def cal_sancov_id_from_local_edge_and_dummy_id(local_edge, dummy_id):
    return int(int(local_edge)/4) + inline_table[dummy_id_2_local_table[dummy_id]]

isStrcmp = {"strcmp", "xmlStrcmp", "xmlStrEqual", "g_strcmp0", "curl_strequal", "strcsequal", "strcasecmp", "stricmp", "ap_cstr_casecmp", "OPENSSL_strcasecmp", "xmlStrcasecmp", "g_strcasecmp", "g_ascii_strcasecmp", "Curl_strcasecompare", "Curl_safe_strcasecompare", "cmsstrcasecmp"}
isMemcmp = {"memcmp", "bcmp", "CRYPTO_memcmp", "OPENSSL_memcmp", "memcmp_const_time", "memcmpct"}
isStrncmp = {"strncmp", "xmlStrncmp", "curl_strnequal", "strncasecmp", "strnicmp", "ap_cstr_casecmpn", "OPENSSL_strncasecmp", "xmlStrncasecmp", "g_ascii_strncasecmp", "Curl_strncasecompare", "g_strncasecmp"}
isStrstr = {"strstr", "g_strstr_len", "ap_strcasestr", "xmlStrstr", "xmlStrcasestr", "g_str_has_prefix", "g_str_has_suffix"}
def recognize_strcmp_subtype(instruction):
    for func in isStrcmp:
        if func in instruction:
            return 'strcmp'

    for func in isMemcmp:
        if func in instruction:
            return 'memcmp'

    for func in isStrncmp:
        if func in instruction:
            return 'strncmp'

    for func in isStrstr:
        if func in instruction:
            return 'strstr'

    return 'error'


if __name__ == '__main__':
    build_sancov_set_from_ll_file(sys.argv[1])
    # check if there is discrepency between llvm IR symbol table and binary's symbol table
    inline_table = inline_counter_table_init(sys.argv[1], sys.argv[2])
    construct_graph_init_from_ll_file(sys.argv[1], inline_table)

    border_edges = []
    select_border_edges = []
    # 0x00 build a map from br_dist_edge_id to local_edge_table(base number)
    # dummy_id_2_local_table
    # read local index from instrument_meta_data, use local_edge_table from last step to compute sancov ID
    # given instrument_meta_data, parse 1) sancov_id to cmp type; 2) [sancov1, sancov2] to cmp type for select;
    # build id_2_cmp_type and select_edge_2_cmp_type
    # id_2_cmp_type: id_2_cmp_type[sancov_id] = (cmp_type, dummy_id, str_len)
    # select_edge_2_cmp_type: select_edge_2_cmp_type[(src_sancov_id, dst_sancov_id)] = (cmp_type, dummy_id, str_len)
    with open(sys.argv[3], 'r') as f:
        for line in f.readlines():
            tokens = line.split('|')
            dummy_id = int(tokens[1])
            if dummy_id not in dummy_id_2_local_table:
                continue
            # not switch and select
            if tokens[0] != '4' and tokens[0] != '3':
                str_len = int(tokens[6])
                sancov_instrument = tokens[2]
                local_edge = parse_local_edge_from_normal_sancov_instrument(sancov_instrument)
                sancov_id = cal_sancov_id_from_local_edge_and_dummy_id(local_edge, dummy_id)

                if tokens[0] == '1':
                    cmp_inst = tokens[3]
                    cmp_type = cmp_inst.split()[3]
                elif tokens[0] == '2':
                    cmp_inst = tokens[3]
                    cmp_type = recognize_strcmp_subtype(cmp_inst)
                    if cmp_type == 'error':
                        print("BUG: error strcmp type")

                id_2_cmp_type[sancov_id] = (cmp_typ_dic[cmp_type], dummy_id, str_len)

            # for switch case
            elif tokens[0] == '3':
                cmp_type = 'switch'
                str_len = int(tokens[6])
                sancov_src_instrument = tokens[2]
                local_src_edge = parse_local_edge_from_normal_sancov_instrument(sancov_src_instrument)
                sancov_src_id = cal_sancov_id_from_local_edge_and_dummy_id(local_src_edge, dummy_id)

                sancov_dst_instrument = tokens[5]
                local_dst_edge = sancov_dst_instrument.split()[16][:-1]
                sancov_dst_id = cal_sancov_id_from_local_edge_and_dummy_id(local_dst_edge, dummy_id)
                id_2_cmp_type[sancov_src_id] = (cmp_typ_dic[cmp_type], -1, str_len)
                sw_border_edge_2_br_dist[(sancov_src_id, sancov_dst_id)] = dummy_id


    # cmp_type[node_id] = cmp_type
    # sancov node_id, cmp_type
    with open("br_node_id_2_cmp_type", "w") as f:
        for node in sorted(global_graph.keys()):
            children = global_graph[node]
            children.sort()
            if len(children) > 1:
                # branch_NO_instrumentation_info
                if node not in id_2_cmp_type:
                    f.write(str(node+6) + " " + str(0) + "\n")
                else:
                    cmp_type = id_2_cmp_type[node][0]
                    f.write(str(node+6) + " " + str(cmp_type) + "\n")

    # build border edge array
    for node in sorted(global_graph.keys()):
        children = global_graph[node]
        children.sort()
        if len(children) > 1:
            for c in children:
                # no instrumentation info
                if node not in id_2_cmp_type:
                    #border_edges.append((node, c, -1, 0, 0, 0))
                    border_edges.append((node, c, -1, 0))
                else:
                    cmp_type = id_2_cmp_type[node][0]
                    dummy_id = id_2_cmp_type[node][1]
                    str_len = id_2_cmp_type[node][2]
                    # switch
                    if cmp_type == 15:
                        border_edges.append((node, c, sw_border_edge_2_br_dist[(node, c)], str_len))
                    # strcmp
                    elif 11<=cmp_type <= 14:
                        border_edges.append((node, c, dummy_id, str_len))
                    # other normal binary br
                    else:
                        border_edges.append((node, c, dummy_id, str_len))

    # border_edge_parent sancov id, boder_edge_child sancov id, border_edge_br_dist_id(i.e., dummy id), str_len
    # DO NOT FORGET to add 1 to the node_id!!!!
    with open("border_edges", "w") as f:
        for parent, child, dummy_id, str_len in border_edges:
            f.write(str(parent+6) + " " + str(child+6) + " " + str(dummy_id) + " " + str(str_len) + "\n")

    parent_node_id_map = defaultdict(list)
    for key, val in enumerate(border_edges):
        parent_node_id_map[val[0]].append(key)

    # border_edge_parent, first_border_edge_idx, num_of_border_edges_starting_from_this_parent
    with open("border_edges_cache", "w") as f:
        for parent, id_list in parent_node_id_map.items():
            f.write(str(parent+6) + " " + str(id_list[0]) + " " + str(id_list[-1] - id_list[0] + 1) + "\n")
            if (id_list[-1] - id_list[0] + 1) <= 1:
                print("BUG: bug in 'border_edges_cache'")

