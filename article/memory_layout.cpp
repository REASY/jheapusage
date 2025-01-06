#include <cstdint>
#include <iostream>

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcHeapSummary.hpp#L76-L93
enum Type
{
    BeforeGC,
    AfterGC,
    GCWhenEndSentinel
};

class HeapWordImpl; // Opaque, never defined.
typedef HeapWordImpl* HeapWord;

class StackObj
{
public:
    void* operator new(size_t size) = delete;
    void* operator new [](size_t size) = delete;
    void operator delete(void* p) = delete;
    void operator delete [](void* p) = delete;
};

class VirtualSpaceSummary : public StackObj
{
    HeapWord* _start;
    HeapWord* _committed_end;
    HeapWord* _reserved_end;

public:
    VirtualSpaceSummary() :
        _start(nullptr), _committed_end(nullptr), _reserved_end(nullptr)
    {
    }

    VirtualSpaceSummary(HeapWord* start, HeapWord* committed_end, HeapWord* reserved_end) :
        _start(start), _committed_end(committed_end), _reserved_end(reserved_end)
    {
    }

    HeapWord* start() const { return _start; }
    HeapWord* committed_end() const { return _committed_end; }
    HeapWord* reserved_end() const { return _reserved_end; }
    size_t committed_size() const { return (uintptr_t)_committed_end - (uintptr_t)_start; }
    size_t reserved_size() const { return (uintptr_t)_reserved_end - (uintptr_t)_start; }
    // Add Inspector as friend class to be able to access private fields.
    // A friend class does not change memory layout of C++ object!
    friend class Inspector;
};

class GCHeapSummary;


class GCHeapSummary : public StackObj
{
    VirtualSpaceSummary _heap;
    size_t _used;

public:
    GCHeapSummary() :
        _heap(), _used(0)
    {
    }

    GCHeapSummary(VirtualSpaceSummary& heap_space, size_t used) :
        _heap(heap_space), _used(used)
    {
    }

    const VirtualSpaceSummary& heap() const { return _heap; }
    size_t used() const { return _used; }

    // Add Inspector as friend class to be able to access private fields.
    // A friend class does not change memory layout of C++ object!
    friend class Inspector;
};

class G1HeapSummary : public GCHeapSummary
{
    size_t _edenUsed;
    size_t _edenCapacity;
    size_t _survivorUsed;
    size_t _oldGenUsed;
    uint _numberOfRegions;

public:
    G1HeapSummary(VirtualSpaceSummary& heap_space, size_t heap_used, size_t edenUsed, size_t edenCapacity,
                  size_t survivorUsed, size_t oldGenUsed, uint numberOfRegions) :
        GCHeapSummary(heap_space, heap_used), _edenUsed(edenUsed), _edenCapacity(edenCapacity),
        _survivorUsed(survivorUsed), _oldGenUsed(oldGenUsed), _numberOfRegions(numberOfRegions)
    {
    }

    const size_t edenUsed() const { return _edenUsed; }
    const size_t edenCapacity() const { return _edenCapacity; }
    const size_t survivorUsed() const { return _survivorUsed; }
    const size_t oldGenUsed() const { return _oldGenUsed; }
    const uint numberOfRegions() const { return _numberOfRegions; }

    // Add Inspector as friend class to be able to access private fields.
    // A friend class does not change memory layout of C++ object!
    friend class Inspector;
};

class Inspector
{
public:
    static void inspectG1HeapSummary(const G1HeapSummary& s)
    {
        const char* start = reinterpret_cast<const char*>(&s);
        std::cout << "The offsets of the fields of G1HeapSummary class" << std::endl;
        std::cout << "\t _heap: " << reinterpret_cast<const char*>(&s._heap) - start << " bytes" << std::endl;
        std::cout << "\t _used: " << reinterpret_cast<const char*>(&s._used) - start << " bytes" << std::endl;
        std::cout << "\t _edenUsed: " << reinterpret_cast<const char*>(&s._edenUsed) - start << " bytes" << std::endl;
        std::cout << "\t _edenCapacity: " << reinterpret_cast<const char*>(&s._edenCapacity) - start << " bytes" <<
            std::endl;
        std::cout << "\t _survivorUsed: " << reinterpret_cast<const char*>(&s._survivorUsed) - start << " bytes" <<
            std::endl;
        std::cout << "\t _oldGenUsed: " << reinterpret_cast<const char*>(&s._oldGenUsed) - start << " bytes" <<
            std::endl;
        std::cout << "\t _numberOfRegions: " << reinterpret_cast<const char*>(&s._numberOfRegions) - start << " bytes"
            << std::endl;
    }

    static void inspectGCHeapSummary(const GCHeapSummary& s)
    {
        const char* start = reinterpret_cast<const char*>(&s);
        std::cout << "The offsets of the fields of GCHeapSummary class" << std::endl;
        std::cout << "\t _heap: " << reinterpret_cast<const char*>(&s._heap) - start << " bytes" << std::endl;
        std::cout << "\t _used: " << reinterpret_cast<const char*>(&s._used) - start << " bytes" << std::endl;
    }
};


struct GCHeapSummaryStruct
{
    uint64_t _start;
    uint64_t _committed_end;
    uint64_t _reserved_end;
    uint64_t _padding;
    size_t used;
};

int main()
{
    std::cout << "sizeof(Type): " << sizeof(Type) << " bytes" << std::endl;
    std::cout << "\t Type::BeforeGC is " << Type::BeforeGC << std::endl;
    std::cout << "\t Type::AfterGC is " << Type::AfterGC << std::endl;
    std::cout << "\t Type::GCWhenEndSentinel is " << Type::GCWhenEndSentinel << std::endl;

    {
        VirtualSpaceSummary vss{};
        GCHeapSummary ghs(vss, 0);
        Inspector::inspectGCHeapSummary(ghs);
    }

    {
        VirtualSpaceSummary vss{};
        G1HeapSummary g1hs(vss, 0, 0, 0, 0, 0, 0);
        Inspector::inspectG1HeapSummary(g1hs);
    }
}
