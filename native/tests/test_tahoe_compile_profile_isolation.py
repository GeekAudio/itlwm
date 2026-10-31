#!/usr/bin/env python3
"""Verify feature isolation in the actual production TU command generator."""
import importlib.util
from pathlib import Path
import subprocess,tempfile,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('profiles',ROOT/'scripts/verify_tahoe_compile_profiles.py')
profiles=importlib.util.module_from_spec(spec);spec.loader.exec_module(profiles)
class ProfileIsolation(unittest.TestCase):
 def test_preowner_macro_does_not_leak_into_other_profiles(self):
  commands=[]
  def compile_command(command,**kwargs):
   commands.append(command)
   return subprocess.CompletedProcess(command,0,'','')
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);log=tmp/'build.log';out=tmp/'report.json'
   log.write_text('\n'.join('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -DITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332=1 -DITL_NATIVE_AWDL_RESIDENT_25G332=1 -c /source/'+unit+' -o /output.o' for unit in profiles.UNITS))
   with patch.object(profiles.subprocess,'run',side_effect=compile_command): profiles.verify(ROOT,log,out)
  self.assertEqual(len(commands),len(profiles.UNITS)*len(profiles.PROFILES))
  for offset in range(0,len(commands),len(profiles.PROFILES)):
   for index,profile in enumerate(profiles.PROFILES):
    command=commands[offset+index]
    count=sum(x.startswith('-DITL_NATIVE_RX_PREOWNER_OBSERVATION_') for x in command)
    self.assertEqual(count,1 if profile=='rx149_preowner' else 0)
    if profile=='ordinary_wifi':self.assertFalse(any(x.startswith('-DITL_NATIVE_AWDL_') for x in command))
    self.assertIn('-fsyntax-only',command);self.assertNotIn('-c',command);self.assertNotIn('-o',command)
 def test_rx_correlation_irq_hook_is_preowner_profile_only(self):
  source=(ROOT/'itlwm/hal_iwx/ItlIwx.cpp').read_text()
  start=source.index('void ItlIwx::tahoeRxPreOwnerIrq(')
  end=source.index('\nvoid ItlIwx::tahoeRxPreOwnerEvent(',start)
  function=source[start:end]
  guard='#if defined(AIRPORT_TAHOE) && defined(ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332)'
  guard_start=function.index(guard)
  guard_end=function.index('#endif',guard_start)
  guarded=function[guard_start:guard_end]
  unguarded=function[:guard_start]+function[guard_end:]
  for symbol in ('tahoeP2pOnMainGate', 'tahoeRxRocCorrelationSync',
                 'nativeRxRocCorrelation_'):
   with self.subTest(symbol=symbol):
    self.assertIn(symbol,guarded)
    self.assertNotIn(symbol,unguarded)
if __name__=='__main__':unittest.main()
