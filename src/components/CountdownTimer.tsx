import { useState, useEffect } from "react";
import { useLanguage } from "@/contexts/LanguageContext";

const CountdownTimer = () => {
  const { t, isRTL } = useLanguage();
  const [timeLeft, setTimeLeft] = useState({
    days: 0,
    hours: 0,
    minutes: 0,
    seconds: 0
  });

  useEffect(() => {
    // Set target date to 7 days from now
    const targetDate = new Date();
    targetDate.setDate(targetDate.getDate() + 7);

    const timer = setInterval(() => {
      const now = new Date().getTime();
      const distance = targetDate.getTime() - now;

      if (distance > 0) {
        setTimeLeft({
          days: Math.floor(distance / (1000 * 60 * 60 * 24)),
          hours: Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)),
          minutes: Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60)),
          seconds: Math.floor((distance % (1000 * 60)) / 1000)
        });
      } else {
        setTimeLeft({ days: 0, hours: 0, minutes: 0, seconds: 0 });
      }
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const TimeUnit = ({ value, label }: { value: number; label: string }) => (
    <div className="text-center">
      <div className="text-4xl md:text-5xl font-bold text-foreground mb-2">
        {value.toString().padStart(2, '0')}
      </div>
      <div className="text-sm text-muted-foreground uppercase tracking-wide">
        {label}
      </div>
    </div>
  );

  return (
    <div className="bg-white rounded-lg p-6 shadow-lg">
      <div className="text-center mb-6">
        <h3 className="text-xl font-heading font-bold text-foreground mb-2">
          {t('offer.limited')}
        </h3>
        <p className="text-muted-foreground">
          {isRTL ? 'تنتهي هذه الترقية في:' : 'Cette promotion se termine dans :'}
        </p>
      </div>
      <div className={`grid grid-cols-4 gap-4 ${isRTL ? 'direction-rtl' : ''}`}>
        <TimeUnit value={timeLeft.days} label={t('countdown.days')} />
        <TimeUnit value={timeLeft.hours} label={t('countdown.hours')} />
        <TimeUnit value={timeLeft.minutes} label={t('countdown.minutes')} />
        <TimeUnit value={timeLeft.seconds} label={t('countdown.seconds')} />
      </div>
    </div>
  );
};

export default CountdownTimer;