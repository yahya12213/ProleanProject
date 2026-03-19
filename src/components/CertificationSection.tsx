import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Search } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";

const CertificationSection = () => {
  const [certificateNumber, setCertificateNumber] = useState("");
  const { t } = useLanguage();

  const handleVerification = () => {
    if (certificateNumber.trim()) {
      // Simulate verification process
      alert(`Vérification du certificat: ${certificateNumber}`);
    }
  };

  return (
    <section className="py-20 bg-neutral">
      <div className="container mx-auto px-4">
        <div className="text-center max-w-2xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-heading font-bold text-foreground mb-8">
            {t('certification.title')}
          </h2>
          
          <div className="flex flex-col md:flex-row gap-4 max-w-md mx-auto">
            <div className="relative flex-1">
              <Input
                type="text"
                placeholder={t('certification.placeholder')}
                value={certificateNumber}
                onChange={(e) => setCertificateNumber(e.target.value)}
                className="pr-10"
              />
              <Search className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            </div>
            <Button 
              onClick={handleVerification}
              className="bg-accent text-accent-foreground hover:bg-accent/90 font-semibold"
            >
              {t('certification.verify')}
            </Button>
          </div>
          
          <p className="text-sm text-muted-foreground mt-4">
            {t('certification.description')}
          </p>
        </div>
      </div>
    </section>
  );
};

export default CertificationSection;