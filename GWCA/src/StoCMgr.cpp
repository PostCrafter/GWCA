#include "stdafx.h"

#include <GWCA/Utilities/Export.h>
#include <GWCA/Utilities/Scanner.h>

#include <GWCA/GameContainers/Array.h>
#include <GWCA/GameContainers/Vector.h>

#include <GWCA/Packets/StoC.h>

#include <GWCA/Managers/StoCMgr.h>

namespace {
    typedef bool(__fastcall *StoCHandler_t)(GW::Packet::StoC::PacketBase* pak);

    struct StoCHandler {
        DWORD* packettemplate;
        int templatesize;
        StoCHandler_t handlerfunc;
    };

    typedef GW::Array<StoCHandler> StoCHandlerArray;

    StoCHandlerArray game_server_handler;
    StoCHandler* original_functions = nullptr;
    std::map<DWORD, std::map<DWORD, GW::StoC::CallbackFunc<GW::Packet::StoC::PacketBase>>> event_calls;
    DWORD last_identifier = 0;

    bool __fastcall StoCHandlerFunc(GW::Packet::StoC::PacketBase* pak) {
        bool do_not_process = false;
        for (auto call : event_calls[pak->header]) {
            if (call.second(pak)) do_not_process = true;
        }
        return do_not_process ? true : original_functions[pak->header].handlerfunc(pak);
    }


    void OriginalHandler(GW::Packet::StoC::PacketBase* packet) {
        original_functions[packet->header].handlerfunc(packet);
    }
}


void GW::StoC::Initialize() {
    // inb4 has rages at this
#if 0
    struct LSObjPtrChain {
        struct {
            struct {
                BYTE pad[0x14];
                struct {
                    BYTE pad[0x8];
                    struct {
                        BYTE pad[0x8];
                        struct {
                            BYTE pad[0x24];
                            StoCHandlerArray gshandlers;
                        } *sub4;
                    } *sub3;
                } *sub2;
            };
        }*sub1;
    } *lsobjbase = *(LSObjPtrChain **)Scanner::Find("\x8B\x56\x04\x85\xC0\x89\x57\x18", "xxxxxxxx", -4);
    game_server_handler = lsobjbase->sub1->sub2->sub3->sub4->gshandlers;
#else
    uintptr_t found = Scanner::Find("\x50\x52\x8B\x55\x0C\xC7\x45\xF8", "xxxxxxxx", -0x23);
    printf("[SCAN] StoCHandler pattern = %p\n", (void *)found);
    if (!found) return;

    struct GameServer {
        BYTE h0000[8];
        struct {
            BYTE h0000[12];
            struct {
                BYTE h0000[12];
                void *next;
                BYTE h0010[12];
                DWORD ClientCodecArray[4];
                StoCHandlerArray handlers;
            } *ls_codec;
            BYTE h0010[12];
            // Client codec
            DWORD ClientCodecArray[4];
            StoCHandlerArray handlers;
        } *gs_codec;
    };

    GameServer **addr = *(GameServer ***)found;
    game_server_handler = (*addr)->gs_codec->handlers;
#endif

    original_functions = new StoCHandler[game_server_handler.size()];

    for (DWORD i = 0; i < game_server_handler.size(); ++i) {
        original_functions[i] = game_server_handler[i];
    }

}

DWORD GW::StoC::AddCallback(DWORD header, std::function<bool(Packet::StoC::PacketBase*)> callback) {
    if (original_functions == nullptr) Initialize();
    last_identifier++;
    event_calls[header][last_identifier] = callback;
    game_server_handler[header].handlerfunc = StoCHandlerFunc;
    return last_identifier;
}

void GW::StoC::RemoveCallback(DWORD header, DWORD identifier) {
    event_calls[header].erase(identifier);
}

void GW::StoC::EmulatePacket(Packet::StoC::PacketBase* packet) {
    if (original_functions == nullptr) Initialize();
    OriginalHandler(packet);
}

void GW::StoC::RestoreHooks() {
    if (original_functions == nullptr) return;
    for (DWORD i = 0; i < game_server_handler.size(); ++i) {
        if (game_server_handler[i].handlerfunc != original_functions[i].handlerfunc) {
            game_server_handler[i].handlerfunc = original_functions[i].handlerfunc;
        }
    }
    delete[] original_functions;
}
