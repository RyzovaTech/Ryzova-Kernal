# SPDX-License-Identifier: AGPL-3.0-only
"""Windows-specific request shape validation. W1 never grants authority or executes PE."""
from __future__ import annotations
from copy import deepcopy
import re

ENVIRONMENT='compact/windows'
ABI='windows-amd64-pe32plus-v1'
PROFILE='console-win32-v1'
LIMITS={
    'pe_file_bytes':4*1024*1024,
    'mapped_image_bytes':64*1024*1024,
    'aggregate_image_buffers_bytes':16*1024*1024,
    'guest_memory_bytes':64*1024*1024,
    'stack_bytes':65536,
    'handles':32,
    'imports':32,
    'modules':4,
    'threads':1,
    'processes':1,
    'instructions':262144,
    'io_bytes_per_call':65536,
    'file_bytes':65536,
}
# Contract allowlist across phases; runtime exports are defined separately in api.c.
APIS={
    'kernel32.dll!GetStdHandle':'W3',
    'kernel32.dll!WriteFile':'W3',
    'kernel32.dll!ExitProcess':'W3',
    'kernel32.dll!GetLastError':'W3',
    'kernel32.dll!SetLastError':'W3',
    'kernel32.dll!GetCommandLineW':'W3',
    'kernel32.dll!GetEnvironmentVariableW':'W3',
    'kernel32.dll!VirtualAlloc':'W3',
    'kernel32.dll!VirtualFree':'W3',
    'kernel32.dll!CreateFileW':'W4',
    'kernel32.dll!ReadFile':'W4',
    'kernel32.dll!CloseHandle':'W4',
    'kernel32.dll!SetFilePointerEx':'W4',
    'kernel32.dll!GetFileSizeEx':'W4',
    'kernel32.dll!FlushFileBuffers':'W4',
}
REF=re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,63}\Z')
RIGHTS={'console':frozenset(('write',)),
        'directory':frozenset(('read','write','create','list','metadata'))}
class ContractError(ValueError):
    pass

def validate_request(request):
    """Return an isolated normalized request, with execution and authority both false.

    The trusted Flex launcher must attach actual capabilities later; a JSON grant
    reference is a request only. Windows paths/host paths are not accepted here.
    """
    fields={'schema','environment','api_major','api_minor','abi','profile','apis','resources','limits'}
    if type(request) is not dict or set(request)!=fields:raise ContractError('invalid request fields')
    if request['schema']!='compact-windows-request/v1' or request['environment']!=ENVIRONMENT:raise ContractError('unsupported Windows contract')
    if type(request['api_major']) is not int or request['api_major']!=1:raise ContractError('unsupported major')
    if type(request['api_minor']) is not int or request['api_minor']!=0:raise ContractError('unsupported minor')
    if request['abi']!=ABI or request['profile']!=PROFILE:raise ContractError('unsupported ABI/profile')
    apis=request['apis']
    if type(apis) is not list or len(apis)>LIMITS['imports']:raise ContractError('invalid imports')
    normalized=[]
    for name in apis:
        if type(name) is not str or len(name)>128 or name.count('!')!=1:raise ContractError('invalid import name')
        module,export=name.split('!');name=module.lower()+'!'+export
        if name not in APIS or name in normalized:raise ContractError('unknown or duplicate import')
        normalized.append(name)
    resources=request['resources']
    if type(resources) is not list or len(resources)>8:raise ContractError('invalid resource requests')
    refs=set();clean=[]
    for resource in resources:
        if type(resource) is not dict or set(resource)!={'ref','kind','rights'}:raise ContractError('invalid resource fields')
        ref,kind,rights=resource['ref'],resource['kind'],resource['rights']
        if type(ref) is not str or not REF.fullmatch(ref) or '..' in ref or ref in refs:raise ContractError('invalid or duplicate opaque reference')
        if type(kind) is not str or kind not in RIGHTS:raise ContractError('unsupported resource kind')
        if type(rights) is not list or not rights or any(type(r) is not str or r not in RIGHTS[kind] for r in rights):raise ContractError('invalid rights')
        if len(set(rights))!=len(rights):raise ContractError('duplicate rights')
        refs.add(ref);clean.append({'ref':ref,'kind':kind,'rights':sorted(rights)})
    limits=request['limits']
    if type(limits) is not dict or set(limits)-set(LIMITS):raise ContractError('unknown limits')
    for key,value in limits.items():
        if type(value) is not int or value<1 or value>LIMITS[key]:raise ContractError('limit out of profile')
    selected=dict(LIMITS,**limits)
    if selected['stack_bytes']>selected['guest_memory_bytes']:raise ContractError('stack exceeds guest memory')
    if selected['pe_file_bytes']>selected['aggregate_image_buffers_bytes']:raise ContractError('main image exceeds aggregate image budget')
    if len(normalized)>selected['imports'] or len({a.split('!')[0] for a in normalized})>selected['modules']:raise ContractError('imports exceed requested limits')
    result=deepcopy(request);result.update(apis=sorted(normalized),resources=clean,limits=selected)
    return {'schema':'compact-windows-validation/v1','status':'contract-only',
            'execution_available':False,'authority_attached':False,
            'windows_execution_qualified':False,'request':result}
