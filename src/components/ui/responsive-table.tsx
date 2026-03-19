import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface ResponsiveTableProps {
  children: ReactNode;
  className?: string;
}

interface ResponsiveTableRowProps {
  children: ReactNode;
  className?: string;
  mobileLayout?: ReactNode;
}

interface ResponsiveTableCellProps {
  children: ReactNode;
  className?: string;
  label?: string;
  hideOnMobile?: boolean;
}

export function ResponsiveTable({ children, className }: ResponsiveTableProps) {
  return (
    <div className={cn("w-full", className)}>
      {/* Desktop Table */}
      <div className="hidden lg:block overflow-x-auto">
        <table className="w-full border-collapse">
          {children}
        </table>
      </div>
      
      {/* Mobile Cards */}
      <div className="lg:hidden space-y-3">
        {children}
      </div>
    </div>
  );
}

export function ResponsiveTableHeader({ children, className }: ResponsiveTableProps) {
  return (
    <thead className={cn("hidden lg:table-header-group", className)}>
      {children}
    </thead>
  );
}

export function ResponsiveTableBody({ children, className }: ResponsiveTableProps) {
  return (
    <tbody className={cn("lg:table-row-group", className)}>
      {children}
    </tbody>
  );
}

export function ResponsiveTableRow({ children, className, mobileLayout }: ResponsiveTableRowProps) {
  if (mobileLayout) {
    return (
      <>
        {/* Desktop Row */}
        <tr className={cn("hidden lg:table-row", className)}>
          {children}
        </tr>
        
        {/* Mobile Card */}
        <div className="lg:hidden bg-card rounded-lg border p-4 shadow-sm">
          {mobileLayout}
        </div>
      </>
    );
  }

  return (
    <tr className={cn("lg:table-row", className)}>
      {children}
    </tr>
  );
}

export function ResponsiveTableCell({ children, className, label, hideOnMobile }: ResponsiveTableCellProps) {
  return (
    <td className={cn(
      "lg:table-cell border-b px-4 py-2",
      hideOnMobile && "hidden lg:table-cell",
      className
    )}>
      {label && (
        <div className="lg:hidden">
          <span className="text-sm font-medium text-muted-foreground">{label}: </span>
        </div>
      )}
      {children}
    </td>
  );
}

export function ResponsiveTableHead({ children, className }: ResponsiveTableCellProps) {
  return (
    <th className={cn("hidden lg:table-cell text-left font-semibold border-b px-4 py-3 bg-muted/50", className)}>
      {children}
    </th>
  );
}