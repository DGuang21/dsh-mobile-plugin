import { useMemo, useState } from 'react';
import { Alert, FlatList, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import { router } from 'expo-router';
import { Ionicons } from '@expo/vector-icons';
import { useDsh } from '../src/useDsh';
import { colors, space } from '../src/theme';
import type { Session } from '../src/protocol/types';

const relativeTime = (iso: string) => {
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
  return minutes < 1 ? 'now' : minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h`;
};

function sessionColor(status: Session['status']) {
  return status === 'running' ? colors.cyan : status === 'waiting_approval' ? colors.amber : status === 'error' ? colors.red : colors.faint;
}

function StatusGlyph({ status }: { status: Session['status'] }) {
  return <View style={[styles.statusDot, { backgroundColor: sessionColor(status) }]} />;
}

function stateCopy(dsh: ReturnType<typeof useDsh>) {
  const state = dsh.state;
  switch (state.name) {
    case 'unpaired':
      return { icon: 'scan-outline' as const, tone: colors.amber, title: 'Pair a workstation', detail: state.reason === 'cleared' ? 'This phone is ready for a new pairing.' : 'Scan the dsh QR code to get started.', action: 'Scan QR', actionType: 'pair' as const };
    case 'scanning':
      return { icon: 'scan-outline' as const, tone: colors.amber, title: 'Scanner ready', detail: 'Point the camera at a dsh pairing code.', action: 'Open scanner', actionType: 'pair' as const };
    case 'pairing':
      return { icon: 'link-outline' as const, tone: colors.amber, title: 'Claiming pairing', detail: state.mode === 'relay' ? 'Opening the secure relay rendezvous.' : 'Contacting the workstation bridge.', action: 'View pairing', actionType: 'pair' as const };
    case 'awaiting-confirmation':
      return { icon: 'keypad-outline' as const, tone: colors.cyan, title: 'Compare the code', detail: `Confirm this code on ${state.bridgeName}.`, action: 'View SAS', actionType: 'pair' as const };
    case 'paired':
      return { icon: 'checkmark-circle-outline' as const, tone: colors.cyan, title: `${state.bridgeName} paired`, detail: 'Opening a secure control channel.', action: 'Refresh', actionType: 'refresh' as const };
    case 'connecting':
      return { icon: 'radio-outline' as const, tone: colors.cyan, title: 'Connecting', detail: state.phase === 'sealing' ? 'Verifying the bridge identity.' : state.phase === 'relay' ? 'Reaching the relay.' : state.phase === 'authenticating' ? 'Authenticating this device.' : 'Opening the live stream.', action: 'Refresh', actionType: 'refresh' as const };
    case 'ready':
      return { icon: 'radio-outline' as const, tone: colors.cyan, title: state.dsh === 'down' ? 'Bridge connected' : 'Live connection', detail: state.dsh === 'down' ? 'The workstation bridge is up; dsh is offline.' : `Stream cursor ${state.lastBseq}.`, action: 'Refresh', actionType: 'refresh' as const };
    case 'harness-offline':
      return { icon: 'desktop-outline' as const, tone: colors.amber, title: 'Workstation offline', detail: 'The bridge is reachable, but dsh is not running.', action: 'Try again', actionType: 'refresh' as const };
    case 'relay-unavailable':
      return { icon: 'cloud-offline-outline' as const, tone: colors.amber, title: 'Relay unavailable', detail: state.code === 'peer-offline' ? 'The paired workstation is not reachable right now.' : 'The secure middle path is unavailable.', action: 'Refresh', actionType: 'refresh' as const };
    case 'resyncing':
      return { icon: 'sync-outline' as const, tone: colors.cyan, title: 'Resyncing', detail: 'Rebuilding the session timeline.', action: 'Refresh', actionType: 'refresh' as const };
    case 'rendezvous-busy':
      return { icon: 'people-outline' as const, tone: colors.amber, title: 'Pairing window busy', detail: 'Open a fresh pairing code on the workstation.', action: 'Scan new QR', actionType: 'pair' as const };
    case 'routing-collision':
      return { icon: 'git-compare-outline' as const, tone: colors.red, title: 'Relay route collision', detail: 'This route is already in use. Pair this phone again.', action: 'Re-pair', actionType: 'pair' as const };
    case 'revoked':
      return { icon: 'ban-outline' as const, tone: colors.red, title: 'Access revoked', detail: 'The workstation no longer trusts this phone.', action: 'Pair again', actionType: 'pair' as const };
    case 'pin-mismatch':
      return { icon: 'warning-outline' as const, tone: colors.red, title: 'Identity mismatch', detail: 'The bridge did not prove the identity saved on this phone.', action: 'Forget bridge', actionType: 'clear' as const };
  }
  return { icon: 'help-circle-outline' as const, tone: colors.muted, title: 'Connection status', detail: 'Check the bridge connection.', action: 'Refresh', actionType: 'refresh' as const };
}

function ConnectionPanel({ dsh }: { dsh: ReturnType<typeof useDsh> }) {
  const copy = stateCopy(dsh);
  const runAction = async () => {
    if (copy.actionType === 'pair') return router.push('/settings');
    if (copy.actionType === 'clear') {
      Alert.alert('Forget workstation?', 'The saved route will be removed from this phone.', [{ text: 'Cancel' }, { text: 'Forget', style: 'destructive', onPress: () => void dsh.clear() }]);
      return;
    }
    try { await dsh.refresh(); } catch { /* state machine owns the error copy */ }
  };
  return <View style={[styles.connectionPanel, { borderColor: `${copy.tone}55` }]}>
    <View style={[styles.connectionIcon, { backgroundColor: `${copy.tone}18` }]}><Ionicons name={copy.icon} size={19} color={copy.tone} /></View>
    <View style={styles.connectionCopy}>
      <View style={styles.connectionTitleRow}><Text style={styles.connectionTitle}>{copy.title}</Text><View style={[styles.statePip, { backgroundColor: copy.tone }]} /></View>
      <Text style={styles.connectionDetail}>{copy.detail}</Text>
      {dsh.state.name === 'awaiting-confirmation' && <Text style={styles.sasInline}>{dsh.state.sas}</Text>}
    </View>
    <Pressable accessibilityRole="button" onPress={() => void runAction()} style={({ pressed }) => [styles.connectionAction, pressed && styles.pressed]}><Text style={[styles.connectionActionText, { color: copy.tone }]}>{copy.action}</Text><Ionicons name="chevron-forward" size={15} color={copy.tone} /></Pressable>
  </View>;
}

export default function SessionsScreen() {
  const dsh = useDsh();
  const [query, setQuery] = useState('');
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState('');
  const filtered = useMemo(() => dsh.sessions.filter((item) => `${item.title} ${item.cwd ?? ''} ${item.branch ?? ''}`.toLowerCase().includes(query.toLowerCase())), [dsh.sessions, query]);
  const create = async () => {
    if (!title.trim()) return;
    try { const session = await dsh.create(title.trim()); setTitle(''); setCreating(false); router.push(`/session/${session.id}`); } catch (error) { Alert.alert('Could not create session', error instanceof Error ? error.message : 'The bridge is not ready.'); }
  };
  return <View style={styles.screen}>
    <View style={styles.header}><View><Text style={styles.eyebrow}>D S H  /  MOBILE CONTROL</Text><Text style={styles.heading}>Workspaces</Text></View><Pressable accessibilityLabel="Open settings" onPress={() => router.push('/settings')} style={styles.iconButton}><Ionicons name="settings-outline" size={20} color={colors.text} /></Pressable></View>
    <ConnectionPanel dsh={dsh} />
    <View style={styles.toolbar}><View style={styles.search}><Ionicons name="search" size={17} color={colors.muted} /><TextInput value={query} onChangeText={setQuery} placeholder="Search sessions" placeholderTextColor={colors.faint} style={styles.searchInput} /></View><Pressable accessibilityLabel="Refresh sessions" onPress={() => void dsh.refresh()} style={styles.refresh}><Ionicons name="refresh-outline" size={18} color={colors.muted} /></Pressable></View>
    <View style={styles.sectionHeader}><Text style={styles.sectionTitle}>SESSIONS</Text><Text style={styles.count}>{filtered.length}</Text></View>
    <FlatList data={filtered} keyExtractor={(item) => item.id} contentContainerStyle={styles.list} renderItem={({ item }) => <Pressable onPress={() => router.push(`/session/${item.id}`)} style={({ pressed }) => [styles.session, pressed && styles.pressed]}><View style={styles.sessionTop}><View style={styles.titleRow}><StatusGlyph status={item.status} /><Text style={styles.sessionTitle} numberOfLines={1}>{item.title}</Text></View><Text style={styles.time}>{relativeTime(item.updatedAt)}</Text></View><Text style={styles.path} numberOfLines={1}>{item.cwd ?? 'Remote workspace'}{item.branch ? `  /  ${item.branch}` : ''}</Text><View style={styles.sessionBottom}><Text style={styles.model}>{item.model ?? 'dsh default'}</Text>{item.status === 'waiting_approval' && <View style={styles.approvalPill}><Ionicons name="shield-checkmark-outline" size={13} color={colors.amber} /><Text style={styles.approvalText}>Action needed</Text></View>}{Boolean(item.unread) && <View style={styles.unread}><Text style={styles.unreadText}>{item.unread}</Text></View>}</View></Pressable>} ListEmptyComponent={<View style={styles.empty}><Ionicons name="file-tray-outline" size={26} color={colors.faint} /><Text style={styles.emptyTitle}>{query ? 'No matching sessions' : dsh.connected ? 'No sessions yet' : 'Pair a workstation to begin'}</Text><Text style={styles.emptyText}>{query ? 'Try a different search.' : dsh.connected ? 'Create a session from the button below.' : 'Your remote sessions will appear here.'}</Text></View>} />
    {dsh.connected && <Pressable accessibilityLabel="Create new session" onPress={() => setCreating(true)} style={styles.fab}><Ionicons name="add" size={22} color={colors.canvas} /><Text style={styles.fabText}>New session</Text></Pressable>}
    {creating && <View style={styles.overlay}><View style={styles.modal}><View style={styles.modalHeader}><View><Text style={styles.modalKicker}>NEW CONTROL THREAD</Text><Text style={styles.modalTitle}>Start a session</Text></View><Pressable accessibilityLabel="Close" onPress={() => setCreating(false)} style={styles.close}><Ionicons name="close" size={20} color={colors.muted} /></Pressable></View><TextInput autoFocus value={title} onChangeText={setTitle} placeholder="Session name" placeholderTextColor={colors.faint} style={styles.input} onSubmitEditing={() => void create()} /><Pressable onPress={() => void create()} style={styles.primary}><Text style={styles.primaryText}>Create session</Text><Ionicons name="arrow-forward" size={17} color={colors.canvas} /></Pressable></View></View>}
    <View style={styles.tabs}><Pressable style={styles.tabActive}><Ionicons name="layers" size={19} color={colors.cyan} /><Text style={styles.tabLabelActive}>Sessions</Text></Pressable><Pressable style={styles.tab} onPress={() => router.push('/activity')}><Ionicons name="pulse-outline" size={19} color={colors.muted} /><Text style={styles.tabLabel}>Activity</Text></Pressable></View>
  </View>;
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.canvas, paddingTop: 52 }, header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: space.xl, paddingBottom: 18 },
  eyebrow: { color: colors.cyan, fontSize: 10, fontWeight: '800', letterSpacing: 1.5 }, heading: { color: colors.text, fontSize: 30, fontWeight: '700', marginTop: 5 }, iconButton: { width: 40, height: 40, borderRadius: 12, alignItems: 'center', justifyContent: 'center', backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border },
  connectionPanel: { marginHorizontal: space.xl, marginBottom: 16, padding: 14, minHeight: 76, backgroundColor: colors.surface, borderWidth: 1, borderRadius: 12, flexDirection: 'row', alignItems: 'center', gap: 11 }, connectionIcon: { width: 38, height: 38, borderRadius: 10, alignItems: 'center', justifyContent: 'center' }, connectionCopy: { flex: 1, minWidth: 0 }, connectionTitleRow: { flexDirection: 'row', alignItems: 'center', gap: 7 }, connectionTitle: { color: colors.text, fontWeight: '700', fontSize: 13 }, statePip: { width: 6, height: 6, borderRadius: 3 }, connectionDetail: { color: colors.muted, fontSize: 11, lineHeight: 16, marginTop: 3 }, sasInline: { color: colors.cyan, fontFamily: 'monospace', fontSize: 19, fontWeight: '800', letterSpacing: 2, marginTop: 8 }, connectionAction: { flexDirection: 'row', alignItems: 'center', gap: 2, paddingVertical: 9, paddingLeft: 4 }, connectionActionText: { fontSize: 11, fontWeight: '800' },
  toolbar: { flexDirection: 'row', gap: 8, marginHorizontal: space.xl }, search: { flex: 1, height: 44, backgroundColor: colors.surface, borderRadius: 9, flexDirection: 'row', alignItems: 'center', paddingHorizontal: 13, gap: 9, borderWidth: 1, borderColor: colors.border }, searchInput: { flex: 1, color: colors.text, fontSize: 14 }, refresh: { width: 44, height: 44, borderRadius: 9, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, alignItems: 'center', justifyContent: 'center' }, sectionHeader: { marginHorizontal: space.xl, marginTop: 23, marginBottom: 9, flexDirection: 'row', alignItems: 'center', gap: 8 }, sectionTitle: { color: colors.muted, fontSize: 10, fontWeight: '800', letterSpacing: 1.3 }, count: { color: colors.faint, fontSize: 11 }, list: { paddingHorizontal: space.xl, paddingBottom: 112 },
  session: { backgroundColor: colors.surface, padding: 16, borderRadius: 10, borderWidth: 1, borderColor: colors.border, marginBottom: 9 }, pressed: { opacity: 0.76, borderColor: colors.cyan }, sessionTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }, titleRow: { flexDirection: 'row', alignItems: 'center', flex: 1, gap: 8 }, statusDot: { width: 8, height: 8, borderRadius: 4 }, sessionTitle: { color: colors.text, fontSize: 15, fontWeight: '600', flex: 1 }, time: { color: colors.faint, fontSize: 11 }, path: { color: colors.muted, fontFamily: 'monospace', fontSize: 11, marginTop: 9 }, sessionBottom: { flexDirection: 'row', alignItems: 'center', marginTop: 14, gap: 8 }, model: { color: colors.faint, fontSize: 11, flex: 1 }, approvalPill: { backgroundColor: colors.amberDim, borderRadius: 5, paddingVertical: 4, paddingHorizontal: 7, flexDirection: 'row', gap: 4, alignItems: 'center' }, approvalText: { color: colors.amber, fontSize: 10, fontWeight: '700' }, unread: { width: 19, height: 19, backgroundColor: colors.cyan, borderRadius: 10, justifyContent: 'center', alignItems: 'center' }, unreadText: { color: colors.canvas, fontSize: 10, fontWeight: '800' }, empty: { alignItems: 'center', marginTop: 48, paddingHorizontal: 20 }, emptyTitle: { color: colors.text, fontWeight: '700', fontSize: 14, marginTop: 12 }, emptyText: { color: colors.muted, fontSize: 12, marginTop: 5, textAlign: 'center' },
  fab: { position: 'absolute', right: space.xl, bottom: 77, backgroundColor: colors.cyan, height: 46, paddingHorizontal: 16, borderRadius: 23, flexDirection: 'row', alignItems: 'center', gap: 7, shadowColor: '#000', shadowOpacity: 0.35, shadowRadius: 8, elevation: 4 }, fabText: { color: colors.canvas, fontWeight: '800', fontSize: 13 }, tabs: { position: 'absolute', left: 0, right: 0, bottom: 0, height: 66, backgroundColor: colors.surface, borderTopWidth: 1, borderTopColor: colors.border, flexDirection: 'row', justifyContent: 'space-around', paddingTop: 10 }, tab: { alignItems: 'center', gap: 3, width: 100 }, tabActive: { alignItems: 'center', gap: 3, width: 100 }, tabLabel: { color: colors.muted, fontSize: 11 }, tabLabelActive: { color: colors.cyan, fontSize: 11, fontWeight: '700' },
  overlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(0,0,0,0.68)', justifyContent: 'flex-end' }, modal: { backgroundColor: colors.elevated, borderTopLeftRadius: 18, borderTopRightRadius: 18, padding: space.xl, paddingBottom: 34, borderTopWidth: 1, borderColor: colors.border }, modalHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 22 }, modalKicker: { color: colors.cyan, fontSize: 10, fontWeight: '800', letterSpacing: 1.1 }, modalTitle: { color: colors.text, fontSize: 20, fontWeight: '700', marginTop: 4 }, close: { width: 34, height: 34, alignItems: 'center', justifyContent: 'center' }, input: { height: 48, backgroundColor: colors.code, borderWidth: 1, borderColor: colors.border, borderRadius: 8, color: colors.text, paddingHorizontal: 13, fontSize: 14, marginBottom: 14 }, primary: { height: 48, backgroundColor: colors.cyan, borderRadius: 8, flexDirection: 'row', justifyContent: 'center', alignItems: 'center', gap: 8 }, primaryText: { color: colors.canvas, fontWeight: '800', fontSize: 14 },
});
