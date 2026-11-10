import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import client from '@/api/client'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { QueryError } from '@/components/QueryError'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatBytesForExport } from '@/lib/export'

export interface FlowNode {
  node_uuid: string
  node_name: string
  state: 'enforce' | 'dry-run' | 'stale' | 'disconnected' | 'kernel_unavailable' | 'not_reporting'
  snapshot: {
    sampled_at: string
    guard_started_at: string
    blocks_applied: number
    firewall: null | {
      sampled_at: string; epoch: string; active_flows: number
      dropped_packets: number; dropped_bytes: number
      input_packets: number; output_packets: number
      input_bytes: number; output_bytes: number
    }
    rates: null | { packets_per_second: number; bytes_per_second: number }
  } | null
}

export function FlowEnforcementCard() {
  const { t, i18n } = useTranslation()
  const [node, setNode] = useState('')
  const [showMissing, setShowMissing] = useState(false)
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['flow-enforcement'],
    queryFn: async () => (await client.get<{ nodes: FlowNode[] }>('/analytics/advanced/flow-enforcement')).data,
    refetchInterval: 15000,
    staleTime: 5000,
  })
  const nodes = data?.nodes ?? []
  const visible = nodes.filter(n => (!node || n.node_uuid === node) && (showMissing || n.snapshot))
  const number = (value: number | undefined) => value === undefined ? '—' : value.toLocaleString(i18n.language)
  return <Card className="mb-5">
    <CardHeader>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <CardTitle className="text-base">{t('flowEnforcement.title')}</CardTitle>
        <Button variant="outline" size="sm" onClick={() => refetch()}>{t('flowEnforcement.refresh')}</Button>
      </div>
      <p className="text-xs text-muted-foreground">{t('flowEnforcement.hint')}</p>
    </CardHeader>
    <CardContent className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <select aria-label={t('flowEnforcement.node')} value={node} onChange={e => setNode(e.target.value)} className="max-w-full rounded border border-[var(--glass-border)] bg-[var(--glass-bg)] p-2">
          <option value="">{t('flowEnforcement.allNodes')}</option>
          {nodes.map(n => <option key={n.node_uuid} value={n.node_uuid}>{n.node_name}</option>)}
        </select>
        <label className="flex items-center gap-2"><input type="checkbox" checked={showMissing} onChange={e => setShowMissing(e.target.checked)} />{t('flowEnforcement.showMissing')}</label>
      </div>
      {isLoading ? <Skeleton className="h-32 w-full" /> : isError ? <QueryError onRetry={refetch} /> : visible.length === 0 ?
        <p className="text-sm text-muted-foreground">{t('flowEnforcement.noData')}</p> :
        <Table><TableHeader><TableRow>
          {['node', 'state', 'active', 'applied', 'dropped', 'rate', 'updated'].map(k => <TableHead key={k}>{t(`flowEnforcement.${k}`)}</TableHead>)}
        </TableRow></TableHeader><TableBody>{visible.map(n => {
          const s = n.snapshot, f = s?.firewall
          const fresh = n.state === 'enforce' || n.state === 'dry-run'
          return <TableRow key={n.node_uuid} className={fresh ? '' : 'opacity-60'}>
            <TableCell className="font-medium min-w-40">{n.node_name}</TableCell>
            <TableCell><Badge variant={n.state === 'enforce' ? 'default' : 'secondary'}>{t(`flowEnforcement.states.${n.state}`)}</Badge></TableCell>
            <TableCell>{number(f?.active_flows)}</TableCell>
            <TableCell title={s ? `${t('flowEnforcement.sinceGuard')} ${new Date(s.guard_started_at).toLocaleString(i18n.language)}` : ''}>{number(s?.blocks_applied)}</TableCell>
            <TableCell title={f ? `${t('flowEnforcement.input')}: ${number(f.input_packets)} / ${t('flowEnforcement.output')}: ${number(f.output_packets)}` : ''}>
              <div>{number(f?.dropped_packets)}</div><div className="text-xs text-muted-foreground">{f ? formatBytesForExport(f.dropped_bytes) : '—'}</div>
            </TableCell>
            <TableCell>{fresh && s?.rates ? `${number(s.rates.packets_per_second)} ${t('flowEnforcement.pps')}` : '—'}</TableCell>
            <TableCell className="text-xs whitespace-nowrap">{s ? new Date(f?.sampled_at ?? s.sampled_at).toLocaleString(i18n.language) : '—'}</TableCell>
          </TableRow>
        })}</TableBody></Table>}
      <p className="text-xs text-muted-foreground">{t('flowEnforcement.countersHint')}</p>
    </CardContent>
  </Card>
}
