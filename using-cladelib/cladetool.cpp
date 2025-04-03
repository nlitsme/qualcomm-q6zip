#include <clade_api.h>
#include <clade2_api.h>
#include <clade2_trace.h>
#include <clade_trace.h>
#include <vector>
#include <span>
#include <cpputils/formatter.h>
#include <cpputils/argparse.h>
#include <cpputils/mmfile.h>
/*
class CladeClient {
    static static_alloc(...) -->  alloc();
    static static_lookup(...) -->  lookup();
    static static_free(...) -->  free();
};
*/

using constbytes = std::span<const uint8_t>;
using mutablebytes = std::span<uint8_t>;
std::string fromzstr(const char*p, size_t n)
{
    auto z = std::find(p, p+n, 0);
    return std::string(p, z);
}
std::ostream& operator<<(std::ostream& os, const clade_memblock_t *m)
{
    return os << stringformat("{%p;%p id:<%s> w:%d a:%x/%x ->:%p}",
            m->prev, m->next, fromzstr(m->id, MEMBLOCK_ID_LEN), 
            m->wordsize, m->addr, m->len, m->data);
}

// alloc 
clade_memblock_t* client_alloc(clade_memblock_t *req, clade_memblock_t *prev, void *mem)
{
    //print("alloc(%p:%s, %p:%s)\n", req, req, prev, prev);

    // iterate over 'req' ring, build new ring with allocated memory.
    clade_memblock_t* cur = req;
    do {
        clade_memblock_t* newblk = (clade_memblock_t*)malloc(sizeof(clade_memblock_t));
        memset(newblk->id, 0, MEMBLOCK_ID_LEN);
        if (prev) {
            // insert before 'prev'
            // [beforeprev] -> newblk -> prev
            prev->prev->next = newblk;
            newblk->prev = prev->prev;
            prev->prev = newblk;
            newblk->next = prev;
        }
        else {
            // first: self-link the block
            newblk->prev = newblk;
            newblk->next = newblk;
            prev= newblk;
        }

        newblk->wordsize = cur->wordsize;
        newblk->addr = cur->addr;
        newblk->len = cur->len;
        newblk->data = (uint8_t*)malloc(cur->len * cur->wordsize);

        //print("  --> %p:%s\n", newblk, newblk);

        cur = cur->next;
    } while (cur != req);
    return prev;
}

// lookup may point to, or copy data from client memory.
clade_memblock_t* client_lookup_nocopy(clade_memblock_t *req, void *mem)
{
    //print("lookup(%p:%s)\n", req, req);

    clade_memblock_t* cur = req;
    do {
        cur->data = (uint8_t*)cur->addr;
        cur = cur->next;
    } while (cur != req);

    return req;
}
clade_memblock_t* client_lookup_copy(clade_memblock_t *req, void *mem)
{
    //print("lookup(%p:%s)\n", req, req);

    clade_memblock_t* cur = req;
    do {
        cur->data = (uint8_t*)malloc(cur->len * cur->wordsize);
        memcpy(cur->data, (uint8_t*)cur->addr, cur->len * cur->wordsize);

        cur = cur->next;
    } while (cur != req);

    return req;
}

// free blocks returned by lookup
clade_error_t client_free_nocopy(clade_memblock_t *req)
{
    //print("free(%p:%s\n", req, req);
    // do nothing, data was pointed to, not alloced+copied.
    return CLADE_OK;
}
clade_error_t client_free_copy(clade_memblock_t *req)
{
    //print("free(%p:%s\n", req, req);

    clade_memblock_t* cur = req;
    do {
        if (req->data) {
            free(req->data);
            req->data = 0;
        }
        cur = req->next;
    } while (cur != req);
    return CLADE_OK;
}

void dumpcfg(const clade_config_t& cfg)
{
    print("cfg: r=%x  lv=%x dl=%d, e=%d, id=%x\n",
            cfg.region, cfg.lib_version,
            cfg.dict_len, cfg.error, cfg.build_id);
    print("pds: ");
    for (int i=0 ; i<cfg.num_pds ; i++)
        print(" (%x,%x)", cfg.pd_params[i].comp, cfg.pd_params[i].exc_hi);
    print("\n");

    print("dicts: ");
    for (int i=0 ; i<cfg.num_dicts ; i++)
        print(" d%d=%p", i, cfg.dicts[i]);
    print("\n");

    print("repl: ");
    for (int i=0 ; i<cfg.num_replaceable_words ; i++)
        print(" %08x", cfg.replaceable_words[i]);
    print("\n");
}

void usage()
{
    print("Usage: tstclade [options] filename\n");
    print("  --dictbytesize SIZE  - default: 0x2000\n");
    print("  --ndicts COUNT       - default: 3\n");
    print("  --dictofs OFS        - default: end-0x6040\n");
    print("  -o,--dataofs         - default: 0\n");
    print("  -l,--datasize        - default: 0x1000\n");
    print("  -v                   - show trace information\n");
}


int main(int argc, char**argv)
{
    std::string fn;

    uint32_t dataofs = 0;        // offset into filename
    uint32_t datasize = 0x1000;  // nr bytes to decompress
    uint32_t dictofs = 0;        // when 0, this will be calculated later.
    uint32_t dictbytesize = 0x2000;  // size of 1 dictionary
    int ndicts = 3;
    int wordsize = 1;
    bool verbose = false;

    for (auto& arg : ArgParser(argc, argv))
        switch (arg.option())
        {
            case 'o': dataofs = arg.getint(); break;
            case 'l': datasize = arg.getint(); break;
            case 'v': verbose = true; break;
            case '-':
                if (arg.match("--dictbytesize"))
                    dictbytesize = arg.getint();
                else if (arg.match("--ndicts"))
                    ndicts = arg.getint();
                else if (arg.match("--dictofs"))
                    dictofs = arg.getint();
                else if (arg.match("--dataofs"))
                    dataofs = arg.getint();
                else if (arg.match("--datasize"))
                    datasize = arg.getint();
                else if (arg.match("--wordsize"))
                    wordsize = arg.getint();
                else {
                    usage();
                    return 1;
                }
                break;

            case -1:
                fn = arg.getstr();
                break;
            default:
                usage();
                return 1;
        }

    if (verbose) {
        clade_set_trace(0xff);
        clade2_set_trace(0xff);
    }

    mappedfile m(fn);

    // default dictofs: endoffile - 0x40 - 3*dictsize
    if (dictofs==0)
        dictofs = m.size()-ndicts*dictbytesize-0x40;

    // load dict.
    std::vector<uint32_t> dict((const uint32_t*)(m.begin() + dictofs), (const uint32_t*)(m.begin() + dictofs + ndicts*dictbytesize));

    // validate dictionary contents
    std::array<uint32_t, 3> expectedbits = { 0x3fffffff, 0x007fffff, 0x0001ffff };
    for (int i=0 ; i<ndicts ; i++)
    {
        uint32_t orval = 0;
        for (int j=0 ; j<dictbytesize/sizeof(uint32_t) ; j++)
            orval |= dict[i*dictbytesize/sizeof(uint32_t) +j];

        // if the orred value does not match, this probably means the dictionary
        // was not properly located.
        if (orval != expectedbits[i]) {
            print("dict %d: got: %08x, expected: %08x\n", i, orval, expectedbits[i]);
        }
    }

    std::vector<uint32_t*> dictptrs;
    for (int i=0 ; i<ndicts ; i++)
        dictptrs.push_back(&dict[i * dictbytesize/sizeof(uint32_t)]);

    paddr_t clade_compressed_ptr = (uint64_t)m.begin()+dataofs;
    paddr_t clade_compressed_ptr_hi = clade_compressed_ptr+datasize;

    std::vector<clade_pd_params_t> pds(1);
    pds[0].comp = clade_compressed_ptr;
    pds[0].exc_hi = clade_compressed_ptr_hi;

    clade_config_t cfg;
    cfg.num_replaceable_words = 0;
    cfg.region = clade_compressed_ptr;
    cfg.num_pds = pds.size();
    cfg.num_dicts = dictptrs.size();
    cfg.dict_len = dictbytesize;
    cfg.pd_params = pds.data();
    cfg.dicts = dictptrs.data();

    auto einit = clade_init(&cfg);
    if (einit) {
        print("init -> %d\n", einit);
        return 1;
    }

    if (verbose)
        dumpcfg(cfg);

    // Create requested memory block
    clade_memblock_t request;
    request.addr = clade_compressed_ptr;
    request.data = (uint8_t*)clade_compressed_ptr;
    request.wordsize = wordsize;

    request.len = datasize/wordsize;
    request.next = &request;
    request.prev = &request;
    // Decompress
    clade_memblock_t* read_block = clade_read(&request, NULL, client_alloc, client_lookup_nocopy, client_free_nocopy);

    //print("r: %p:%s\n", read_block, read_block);
    print("data: %-0b\n", constbytes(read_block->data, read_block->len*read_block->wordsize));

    free_memblocks_data(read_block);
}
