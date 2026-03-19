import { useEffect } from "react";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";

const NotificationToast = () => {
  const { toast } = useToast();
  const { t } = useLanguage();

  useEffect(() => {
    // Show welcome notification after 3 seconds
    const timer = setTimeout(() => {
      toast({
        title: t('notifications.welcome'),
        description: t('notifications.welcomeDescription'),
        duration: 5000,
      });
    }, 3000);

    return () => clearTimeout(timer);
  }, [toast, t]);

  useEffect(() => {
    // Show special offer notification after 30 seconds
    const timer = setTimeout(() => {
      toast({
        title: t('notifications.specialOffer'),
        description: t('notifications.specialOfferDescription'),
        duration: 8000,
      });
    }, 30000);

    return () => clearTimeout(timer);
  }, [toast, t]);

  return null;
};

export default NotificationToast;