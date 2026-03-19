import React from "react";
import { cn } from "@/lib/utils";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export interface EnhancedTableProps extends React.HTMLAttributes<HTMLTableElement> {
  children: React.ReactNode;
}

export const EnhancedTable = React.forwardRef<HTMLTableElement, EnhancedTableProps>(
  ({ className, children, ...props }, ref) => {
    return (
      <Table
        ref={ref}
        className={cn("data-table", className)}
        {...props}
      >
        {children}
      </Table>
    );
  }
);

EnhancedTable.displayName = "EnhancedTable";

export interface EnhancedTableHeaderProps extends React.HTMLAttributes<HTMLTableSectionElement> {
  children: React.ReactNode;
}

export const EnhancedTableHeader = React.forwardRef<HTMLTableSectionElement, EnhancedTableHeaderProps>(
  ({ className, children, ...props }, ref) => {
    return (
      <TableHeader
        ref={ref}
        className={cn("", className)}
        {...props}
      >
        {children}
      </TableHeader>
    );
  }
);

EnhancedTableHeader.displayName = "EnhancedTableHeader";

export interface EnhancedTableHeadProps extends React.ThHTMLAttributes<HTMLTableCellElement> {
  children: React.ReactNode;
  numeric?: boolean;
}

export const EnhancedTableHead = React.forwardRef<HTMLTableCellElement, EnhancedTableHeadProps>(
  ({ className, children, numeric = false, ...props }, ref) => {
    return (
      <TableHead
        ref={ref}
        className={cn(
          numeric && "text-right",
          className
        )}
        {...props}
      >
        {children}
      </TableHead>
    );
  }
);

EnhancedTableHead.displayName = "EnhancedTableHead";

export interface EnhancedTableBodyProps extends React.HTMLAttributes<HTMLTableSectionElement> {
  children: React.ReactNode;
}

export const EnhancedTableBody = React.forwardRef<HTMLTableSectionElement, EnhancedTableBodyProps>(
  ({ className, children, ...props }, ref) => {
    return (
      <TableBody
        ref={ref}
        className={cn("", className)}
        {...props}
      >
        {children}
      </TableBody>
    );
  }
);

EnhancedTableBody.displayName = "EnhancedTableBody";

export interface EnhancedTableRowProps extends React.HTMLAttributes<HTMLTableRowElement> {
  children: React.ReactNode;
  interactive?: boolean;
}

export const EnhancedTableRow = React.forwardRef<HTMLTableRowElement, EnhancedTableRowProps>(
  ({ className, children, interactive = false, ...props }, ref) => {
    return (
      <TableRow
        ref={ref}
        className={cn(
          interactive && "cursor-pointer",
          className
        )}
        {...props}
      >
        {children}
      </TableRow>
    );
  }
);

EnhancedTableRow.displayName = "EnhancedTableRow";

export interface EnhancedTableCellProps extends React.TdHTMLAttributes<HTMLTableCellElement> {
  children: React.ReactNode;
  numeric?: boolean;
}

export const EnhancedTableCell = React.forwardRef<HTMLTableCellElement, EnhancedTableCellProps>(
  ({ className, children, numeric = false, ...props }, ref) => {
    return (
      <TableCell
        ref={ref}
        className={cn(
          numeric && "numeric",
          className
        )}
        {...props}
      >
        {children}
      </TableCell>
    );
  }
);

EnhancedTableCell.displayName = "EnhancedTableCell";