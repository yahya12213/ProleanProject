import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { RotateCcw, CalendarIcon, Calculator } from "lucide-react";
import { format } from "date-fns";
import { fr } from "date-fns/locale";
import { cn } from "@/lib/utils";

interface PointageFiltersProps {
  selectedYear: string;
  selectedMonth: string;
  dateDebut?: Date;
  dateFin?: Date;
  onYearChange: (year: string) => void;
  onMonthChange: (month: string) => void;
  onDateDebutChange: (date: Date | undefined) => void;
  onDateFinChange: (date: Date | undefined) => void;
  onReset: () => void;
  availableYears: string[];
  totalPointages: number;
  totalHeures: number;
  heuresCalculees?: number;
}

const months = [
  { value: "1", label: "Janvier" },
  { value: "2", label: "Février" },
  { value: "3", label: "Mars" },
  { value: "4", label: "Avril" },
  { value: "5", label: "Mai" },
  { value: "6", label: "Juin" },
  { value: "7", label: "Juillet" },
  { value: "8", label: "Août" },
  { value: "9", label: "Septembre" },
  { value: "10", label: "Octobre" },
  { value: "11", label: "Novembre" },
  { value: "12", label: "Décembre" },
];

export function PointageFilters({
  selectedYear,
  selectedMonth,
  dateDebut,
  dateFin,
  onYearChange,
  onMonthChange,
  onDateDebutChange,
  onDateFinChange,
  onReset,
  availableYears,
  totalPointages,
  totalHeures,
  heuresCalculees
}: PointageFiltersProps) {
  return (
    <Card className="p-4 mb-4">
      <div className="space-y-4">
        {/* Première ligne: Filtres traditionnels */}
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
            <div className="flex gap-2">
              <Select value={selectedYear} onValueChange={onYearChange}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Année" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Toutes</SelectItem>
                  {availableYears.map((year) => (
                    <SelectItem key={year} value={year}>
                      {year}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={selectedMonth} onValueChange={onMonthChange}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Mois" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous</SelectItem>
                  {months.map((month) => (
                    <SelectItem key={month.value} value={month.value}>
                      {month.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Button variant="outline" size="sm" onClick={onReset}>
                <RotateCcw className="h-4 w-4 mr-1" />
                Reset
              </Button>
            </div>
          </div>
        </div>

        {/* Deuxième ligne: Filtre par fourchette de dates */}
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
          <div className="flex gap-2 items-center">
            <span className="text-sm font-medium text-foreground">Période :</span>
            
            <Popover>
              <PopoverTrigger asChild>
                <Button
                  variant="outline"
                  className={cn(
                    "w-[130px] justify-start text-left font-normal",
                    !dateDebut && "text-muted-foreground"
                  )}
                >
                  <CalendarIcon className="mr-2 h-4 w-4" />
                  {dateDebut ? format(dateDebut, "dd/MM/yyyy", { locale: fr }) : "Du..."}
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0" align="start">
                <Calendar
                  mode="single"
                  selected={dateDebut}
                  onSelect={onDateDebutChange}
                  initialFocus
                  className={cn("p-3 pointer-events-auto")}
                />
              </PopoverContent>
            </Popover>

            <span className="text-sm text-muted-foreground">au</span>

            <Popover>
              <PopoverTrigger asChild>
                <Button
                  variant="outline"
                  className={cn(
                    "w-[130px] justify-start text-left font-normal",
                    !dateFin && "text-muted-foreground"
                  )}
                >
                  <CalendarIcon className="mr-2 h-4 w-4" />
                  {dateFin ? format(dateFin, "dd/MM/yyyy", { locale: fr }) : "Au..."}
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0" align="start">
                <Calendar
                  mode="single"
                  selected={dateFin}
                  onSelect={onDateFinChange}
                  initialFocus
                  className={cn("p-3 pointer-events-auto")}
                />
              </PopoverContent>
            </Popover>
          </div>
        </div>

        {/* Troisième ligne: Statistiques avec heures calculées */}
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between border-t pt-3">
          <div className="flex gap-6 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">{totalPointages} pointage(s)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Total:</span>
              <span className="font-medium">{totalHeures.toFixed(1)}h</span>
            </div>
            {heuresCalculees !== undefined && dateDebut && dateFin && (
              <div className="flex items-center gap-2 px-3 py-1 bg-primary/10 rounded-md">
                <Calculator className="h-4 w-4 text-primary" />
                <span className="text-muted-foreground">Heures calculées:</span>
                <span className="font-bold text-lg text-primary">
                  {heuresCalculees.toFixed(1)}h
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </Card>
  );
}