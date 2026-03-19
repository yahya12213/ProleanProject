import { ReactNode, useState } from "react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Menu } from "lucide-react";
import { cn } from "@/lib/utils";

interface MobileDrawerProps {
  children: ReactNode;
  trigger?: ReactNode;
  title?: string;
  description?: string;
  className?: string;
}

export function MobileDrawer({ 
  children, 
  trigger, 
  title = "Menu", 
  description, 
  className 
}: MobileDrawerProps) {
  const [open, setOpen] = useState(false);

  const defaultTrigger = (
    <Button variant="outline" size="icon" className="md:hidden">
      <Menu className="h-4 w-4" />
    </Button>
  );

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        {trigger || defaultTrigger}
      </SheetTrigger>
      <SheetContent side="left" className={cn("w-80 sm:w-96", className)}>
        <SheetHeader className="mb-6">
          <SheetTitle className="text-lg">{title}</SheetTitle>
          {description && (
            <SheetDescription className="text-sm">
              {description}
            </SheetDescription>
          )}
        </SheetHeader>
        <div className="space-y-4 overflow-y-auto max-h-[calc(100vh-120px)]">
          {children}
        </div>
      </SheetContent>
    </Sheet>
  );
}

export function MobileDrawerSection({ children, title, className }: { 
  children: ReactNode; 
  title?: string; 
  className?: string; 
}) {
  return (
    <div className={cn("space-y-3", className)}>
      {title && (
        <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
          {title}
        </h3>
      )}
      <div className="space-y-2">
        {children}
      </div>
    </div>
  );
}