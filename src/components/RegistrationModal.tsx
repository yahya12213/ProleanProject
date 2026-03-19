import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useLanguage } from "@/contexts/LanguageContext";
import { useCurrency } from "@/contexts/CurrencyContext";
import { useToast } from "@/hooks/use-toast";
import LoadingSpinner from "./LoadingSpinner";

interface RegistrationModalProps {
  isOpen: boolean;
  onClose: () => void;
  formationTitle: string;
  formationPrice: number;
}

const RegistrationModal = ({ isOpen, onClose, formationTitle, formationPrice }: RegistrationModalProps) => {
  const { t } = useLanguage();
  const { formatPrice, currency } = useCurrency();
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
  
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    company: "",
    experience: "",
    motivation: "",
    paymentMethod: ""
  });

  const handleChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    // Simulate API call
    try {
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      toast({
        title: t('registration.success'),
        description: t('registration.successDescription'),
      });
      
      // Reset form
      setFormData({
        firstName: "",
        lastName: "",
        email: "",
        phone: "",
        company: "",
        experience: "",
        motivation: "",
        paymentMethod: ""
      });
      
      onClose();
    } catch (error) {
      toast({
        title: t('registration.error'),
        description: t('registration.errorDescription'),
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-2xl font-heading">
            {t('registration.title')}
          </DialogTitle>
          <DialogDescription>
            {t('registration.subtitle')} <strong>{formationTitle}</strong>
            <br />
            <span className="text-lg font-semibold text-primary mt-2 block">
              {formatPrice(formationPrice)}
            </span>
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <Label htmlFor="firstName">{t('registration.firstName')}</Label>
              <Input
                id="firstName"
                value={formData.firstName}
                onChange={(e) => handleChange("firstName", e.target.value)}
                required
              />
            </div>
            <div>
              <Label htmlFor="lastName">{t('registration.lastName')}</Label>
              <Input
                id="lastName"
                value={formData.lastName}
                onChange={(e) => handleChange("lastName", e.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <Label htmlFor="email">{t('registration.email')}</Label>
            <Input
              id="email"
              type="email"
              value={formData.email}
              onChange={(e) => handleChange("email", e.target.value)}
              required
            />
          </div>

          <div>
            <Label htmlFor="phone">{t('registration.phone')}</Label>
            <Input
              id="phone"
              type="tel"
              value={formData.phone}
              onChange={(e) => handleChange("phone", e.target.value)}
              required
            />
          </div>

          <div>
            <Label htmlFor="company">{t('registration.company')}</Label>
            <Input
              id="company"
              value={formData.company}
              onChange={(e) => handleChange("company", e.target.value)}
            />
          </div>

          <div>
            <Label htmlFor="experience">{t('registration.experience')}</Label>
            <Select onValueChange={(value) => handleChange("experience", value)}>
              <SelectTrigger>
                <SelectValue placeholder={t('registration.selectExperience')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="beginner">{t('registration.beginner')}</SelectItem>
                <SelectItem value="intermediate">{t('registration.intermediate')}</SelectItem>
                <SelectItem value="advanced">{t('registration.advanced')}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label htmlFor="motivation">{t('registration.motivation')}</Label>
            <Textarea
              id="motivation"
              value={formData.motivation}
              onChange={(e) => handleChange("motivation", e.target.value)}
              placeholder={t('registration.motivationPlaceholder')}
              rows={3}
            />
          </div>

          <div>
            <Label htmlFor="paymentMethod">{t('registration.paymentMethod')}</Label>
            <Select onValueChange={(value) => handleChange("paymentMethod", value)} required>
              <SelectTrigger>
                <SelectValue placeholder={t('registration.selectPayment')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="stripe">{t('registration.creditCard')}</SelectItem>
                <SelectItem value="bank">{t('registration.bankTransfer')}</SelectItem>
                <SelectItem value="installment">{t('registration.installment')}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex gap-4 pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              className="flex-1"
              disabled={isLoading}
            >
              {t('common.cancel')}
            </Button>
            <Button
              type="submit"
              className="flex-1 bg-primary text-primary-foreground hover:bg-primary/90"
              disabled={isLoading}
            >
              {isLoading ? (
                <LoadingSpinner size="sm" />
              ) : (
                t('registration.submit')
              )}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default RegistrationModal;