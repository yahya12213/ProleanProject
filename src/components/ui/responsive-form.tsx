import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface ResponsiveFormProps {
  children: ReactNode;
  className?: string;
}

interface ResponsiveFormGridProps {
  children: ReactNode;
  className?: string;
  cols?: {
    mobile?: number;
    tablet?: number;
    desktop?: number;
  };
}

interface ResponsiveFormFieldProps {
  children: ReactNode;
  className?: string;
  span?: {
    mobile?: number;
    tablet?: number;
    desktop?: number;
  };
}

export function ResponsiveForm({ children, className }: ResponsiveFormProps) {
  return (
    <form className={cn("space-y-4 sm:space-y-6", className)}>
      {children}
    </form>
  );
}

export function ResponsiveFormGrid({ children, className, cols = { mobile: 1, tablet: 2, desktop: 3 } }: ResponsiveFormGridProps) {
  const gridClasses = cn(
    "grid gap-3 sm:gap-4 lg:gap-6",
    `grid-cols-${cols.mobile}`,
    cols.tablet && `sm:grid-cols-${cols.tablet}`,
    cols.desktop && `lg:grid-cols-${cols.desktop}`,
    className
  );

  return (
    <div className={gridClasses}>
      {children}
    </div>
  );
}

export function ResponsiveFormField({ children, className, span }: ResponsiveFormFieldProps) {
  const spanClasses = cn(
    span?.mobile && `col-span-${span.mobile}`,
    span?.tablet && `sm:col-span-${span.tablet}`,
    span?.desktop && `lg:col-span-${span.desktop}`,
    className
  );

  return (
    <div className={spanClasses}>
      {children}
    </div>
  );
}

export function ResponsiveFormSection({ children, className }: ResponsiveFormProps) {
  return (
    <div className={cn("space-y-3 sm:space-y-4 p-4 sm:p-6 border rounded-lg bg-card/50", className)}>
      {children}
    </div>
  );
}

export function ResponsiveFormActions({ children, className }: ResponsiveFormProps) {
  return (
    <div className={cn("flex flex-col sm:flex-row gap-3 sm:gap-4 pt-4 sm:pt-6 border-t", className)}>
      {children}
    </div>
  );
}