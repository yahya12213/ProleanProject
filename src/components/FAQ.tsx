
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { useLanguage } from "@/contexts/LanguageContext";
import { useData } from "@/contexts/DataContext";
import { Skeleton } from "@/components/ui/skeleton";

const FAQ = () => {
  const { t } = useLanguage();
  const { faqs, isLoading } = useData();

  return (
    <section id="faq" className="py-20 bg-neutral">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-heading font-bold text-foreground mb-4">
            {t('faq.title')}
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            {t('faq.subtitle')}
          </p>
        </div>
        
        <div className="max-w-4xl mx-auto">
          <Accordion type="single" collapsible className="space-y-4">
            {isLoading ? (
              Array.from({ length: 4 }).map((_, index) => (
                <div key={index} className="bg-white rounded-lg border border-border shadow-sm p-4">
                  <Skeleton className="h-6 w-3/4" />
                </div>
              ))
            ) : (
              faqs.map((item, index) => (
                <AccordionItem 
                  key={item.id} 
                  value={`item-${index}`}
                  className="bg-white rounded-lg border border-border shadow-sm"
                >
                  <AccordionTrigger className="px-6 py-4 text-left font-semibold text-foreground hover:text-primary transition-colors">
                    {item.question}
                  </AccordionTrigger>
                  <AccordionContent className="px-6 pb-4 text-muted-foreground leading-relaxed">
                    {item.answer}
                  </AccordionContent>
                </AccordionItem>
              ))
            )}
          </Accordion>
        </div>
      </div>
    </section>
  );
};

export default FAQ;
