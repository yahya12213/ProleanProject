
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export type RankingRow = {
  rank: number;
  profile_id: string;
  fullName: string;
  photo_url?: string | null;
  segment_logo?: string | null;
  totalInscrits: number;
  totalRates: number;
};

export default function RankingsTable({ rows }: { rows: RankingRow[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Rang</TableHead>
          <TableHead>Assistant</TableHead>
          <TableHead>Segment</TableHead>
          <TableHead>Inscrits</TableHead>
          <TableHead>Inscrits ratés</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((r) => (
          <TableRow key={r.profile_id}>
            <TableCell>#{r.rank}</TableCell>
            <TableCell>
              <div className="flex items-center gap-3">
                <Avatar className="h-8 w-8">
                  <AvatarImage src={r.photo_url || undefined} />
                  <AvatarFallback>{r.fullName?.slice(0, 2)?.toUpperCase() || "PR"}</AvatarFallback>
                </Avatar>
                <span className="font-medium">{r.fullName}</span>
              </div>
            </TableCell>
            <TableCell>
              {r.segment_logo ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img src={r.segment_logo} alt="Segment" className="h-6 w-6 rounded-sm" />
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </TableCell>
            <TableCell>{r.totalInscrits}</TableCell>
            <TableCell>{r.totalRates}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
