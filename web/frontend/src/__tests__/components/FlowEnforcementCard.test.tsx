import { render, screen } from '@testing-library/react'
import { vi, describe, it, expect } from 'vitest'
import { FlowEnforcementCard } from '@/components/FlowEnforcementCard'
const mock = vi.hoisted(() => ({ data: { nodes: [] as any[] }, isLoading: false, isError: false, refetch: vi.fn() }))
vi.mock('@tanstack/react-query', () => ({ useQuery: () => mock }))

describe('FlowEnforcementCard', () => {
  it('distinguishes missing telemetry from zero traffic', () => {
    mock.data = { nodes: [{node_uuid:'a',node_name:'Other node',state:'not_reporting',snapshot:null}] }
    render(<FlowEnforcementCard />)
    expect(screen.getByText(/Отчётов блокировщика пока нет/)).toBeInTheDocument()
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })
  it('shows actual counters and marks stale data', () => {
    mock.data = { nodes: [{node_uuid:'b',node_name:'Test node',state:'stale',snapshot:{sampled_at:'2026-11-10T10:00:00Z',guard_started_at:'2026-11-10T09:00:00Z',blocks_applied:3,firewall:{sampled_at:'2026-11-10T10:00:00Z',epoch:'a',active_flows:2,dropped_packets:17,dropped_bytes:2048,input_packets:7,output_packets:10},rates:{packets_per_second:2}}}] }
    render(<FlowEnforcementCard />)
    expect(screen.getByText('Данные устарели')).toBeInTheDocument()
    expect(screen.getByText('17')).toBeInTheDocument()
    expect(screen.getByText('2.00 KB')).toBeInTheDocument()
    expect(screen.queryByText('2 пак./с')).not.toBeInTheDocument()
  })
})
