import idaapi
import ida_bytes
import idautils

def main():
    patterns = {
        'call eax': b'\xFF\xD0',
        'call ebx': b'\xFF\xD3',
        'call ecx': b'\xFF\xD1',
        'call edx': b'\xFF\xD2',
        'call esi': b'\xFF\xD6',
        'call edi': b'\xFF\xD7',
        'call esp': b'\xFF\xD4',
        'call ebp': b'\xFF\xD5',
        'jump eax': b'\xFF\xE0'

    }
    
    for name, pattern in patterns.items():
        print('Iterating ' + name)
        ea=ida_ida.inf_get_min_ea()
        while ea < ida_ida.inf_get_max_ea():
            ea = ida_bytes.bin_search(ea, ida_ida.inf_get_max_ea(),pattern,None,1,ida_bytes.BIN_SEARCH_FORWARD|ida_bytes.BIN_SEARCH_NOBREAK|ida_bytes.BIN_SEARCH_NOSHOW)
            if ea == ida_idaapi.BADADDR:
                # not found
                print('Ending: ' + name)
                break
            else:
                print(ea)
                idc.add_bpt(ea)
                ea += 1
    
if __name__== '__main__':
    main()
