import idaapi
import ida_bytes
import idautils
import ida_funcs

def main():
    next=idaapi.cvar.inf.min_ea
    while next!= idaapi.BADADDR:
        next=ida_search.find_not_func(next, SEARCH_DOWN)
        flags= ida_bytes.get_flags(next)
        if ida_bytes.is_code(flags):
            ida_funcs.add_func(next)
if __name__== '__main__':
    main()