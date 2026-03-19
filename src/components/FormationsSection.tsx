
import { useData } from "@/contexts/DataContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";
import { EnhancedCard, EnhancedCardHeader, EnhancedCardTitle, EnhancedCardDescription, EnhancedCardContent } from "@/components/ui/enhanced-card";

const FormationsSection = () => {
  const { formations, isLoading } = useData();
  const { t } = useLanguage();

  return (
    <section id="formations" className="py-20 px-4 bg-slate-900 text-white">
      <div className="container mx-auto">
        <div className="text-center mb-12">
          <h2 className="text-5xl font-heading font-bold mb-4 text-shadow-hero">{t('formations.title')}</h2>
          <p className="text-xl text-slate-300 max-w-3xl mx-auto">{t('formations.subtitle')}</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {isLoading ? (
            Array.from({ length: 3 }).map((_, index) => (
              <div key={index} className="bg-slate-800 p-6 rounded-lg">
                <Skeleton className="h-8 w-3/4 mb-4" />
                <Skeleton className="h-4 w-full mb-2" />
                <Skeleton className="h-4 w-5/6 mb-6" />
                <Skeleton className="h-10 w-full mt-8" />
              </div>
            ))
          ) : (
            formations.map((formation) => (
              <EnhancedCard key={formation.id}>
                <EnhancedCardHeader>
                  <EnhancedCardTitle>{formation.title}</EnhancedCardTitle>
                  <EnhancedCardDescription>{formation.description}</EnhancedCardDescription>
                </EnhancedCardHeader>
                <EnhancedCardContent>
                  <Button className="w-full bg-gradient-primary text-primary-foreground hover:opacity-95 transition-all group mt-auto">
                    {t('formations.cta')} <ArrowRight className="ml-2 h-5 w-5 transform transition-transform group-hover:translate-x-1" />
                  </Button>
                </EnhancedCardContent>
              </EnhancedCard>
            ))
          )}
        </div>
      </div>
    </section>
  );
};

export default FormationsSection;
